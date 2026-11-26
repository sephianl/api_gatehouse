defmodule ApiGatehouse.Plug.Token do
  @moduledoc """
  The token endpoint: issues an opaque access token for the `client_credentials`
  grant, and rotates a refresh token for the `refresh_token` grant.

      post "/api/oauth/token", ApiGatehouse.Plug.Token, []

  in a scope piped through a pipeline that starts with `ApiGatehouse.Plug.Server`.
  The host's endpoint must parse urlencoded (and, if it likes, JSON) bodies.

  Both grants first authenticate the client (`ApiGatehouse.OAuth.ClientAuth`):
  HTTP Basic or `client_id`/`client_secret` in the body, never both; a deleted
  client does not authenticate. Then the client's owner has to load through
  `c:ApiGatehouse.Server.load_owner/2`, so a demoted or removed owner's
  credentials stop working at once. Either failure is a 401 `invalid_client`.

  `scope` narrows the token to some of what the client may have; asking for a
  scope outside it is `invalid_scope`. See `ApiGatehouse.OAuth.Scopes`.

  ## Refresh

  The refresh grant requires client authentication too (RFC 6749 §6), and the
  refresh token must have been issued to the authenticated client. It rotates:
  the presented row is revoked and a new access and refresh token issued, so
  each refresh token works once and each new one gets a fresh
  `c:ApiGatehouse.Server.refresh_idle_ttl/0`; one left unused that long expires.
  On top of that:

    * A revoked refresh token presented again by its own client revokes every
      live token of its family — the client, its owner and company (RFC 9700
      §4.14.2): one of the two parties holding it is not the client. A
      presentation within five seconds of the revocation is treated as the
      client's own concurrent retry and only refused. The rule applies to a
      refresh token however it was revoked: rotated, revoked through
      `ApiGatehouse.Plug.Revocation`, or revoked with its family.
    * With `c:ApiGatehouse.Server.issue_refresh_token?/0` false, no refresh
      token is issued and the grant is `unauthorized_client`.

  A client that loses a refresh response and retries after the grace period
  revokes its own tokens; that is the RFC's accepted trade-off, and the client
  can always obtain a new token with its credentials.

  ## Responses

  Success is RFC 6749 §5.1: `access_token`, `token_type` `"Bearer"`,
  `expires_in`, `scope`, and `refresh_token` when one was issued. Errors are
  §5.2 (see `ApiGatehouse.Plug.OAuthError`). Every response is marked
  `no-store`. Losing a rotation race is an `invalid_grant`; any other failure a
  500 `server_error`, logged without any token or secret.
  """
  @behaviour Plug

  alias ApiGatehouse.OAuth.ClientAuth
  alias ApiGatehouse.OAuth.Lookup
  alias ApiGatehouse.OAuth.Scopes
  alias ApiGatehouse.OAuth.ServerActor
  alias ApiGatehouse.Plug.Json
  alias ApiGatehouse.Plug.NoStore
  alias ApiGatehouse.Plug.OAuthError
  alias ApiGatehouse.Plug.Options
  alias ApiGatehouse.Server.Callbacks
  alias ApiGatehouse.Telemetry

  require Logger

  @replay_grace_ms 5_000
  @grant_types %{"client_credentials" => :client_credentials, "refresh_token" => :refresh_token}

  @impl Plug
  @spec init(keyword()) :: map()
  def init(opts), do: Options.validate(__MODULE__, opts)

  @impl Plug
  @spec call(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def call(conn, opts) do
    server = Options.server(conn, __MODULE__, opts)
    conn = NoStore.call(conn, [])
    params = ClientAuth.body_params(conn)
    grant_type = Map.get(@grant_types, params["grant_type"])

    case grant(conn, server, grant_type, params) do
      {:ok, client, issued, ttl} ->
        Telemetry.emit(
          [:token, :issued],
          %{},
          %{
            grant_type: grant_type,
            client_id: client.client_id,
            owner_id: issued.owner_id,
            company_id: issued.company_id,
            scopes: issued.scopes
          },
          conn,
          server
        )

        respond(conn, issued, ttl)

      {:error, code, description, method, client} ->
        Telemetry.emit(
          [:token, :refused],
          %{},
          %{
            grant_type: grant_type,
            error: code,
            description: description,
            client_id: client && client.client_id
          },
          conn,
          server
        )

        OAuthError.send_error(conn, code, description, method)
    end
  end

  defp grant(conn, server, grant_type, params) when grant_type in [:client_credentials, :refresh_token] do
    case ClientAuth.authenticate(conn, server) do
      {:ok, client, method} ->
        conn |> grant(server, grant_type, params, client, method) |> for_client(client)

      {:error, code, description, method} ->
        {:error, code, description, method, nil}
    end
  end

  defp grant(_conn, _server, nil, %{"grant_type" => grant_type}) when is_binary(grant_type) and grant_type != "",
    do: {:error, :unsupported_grant_type, "the grant type is not supported", :none, nil}

  defp grant(_conn, _server, nil, _params), do: {:error, :invalid_request, "grant_type is required", :none, nil}

  defp grant(_conn, server, :client_credentials, params, client, method) do
    with :ok <- owner_loads(server, client, method),
         {:ok, scopes} <-
           grant_scopes(params["scope"], [client.scopes, Callbacks.scopes(server)], method) do
      issue(server, client, scopes, method)
    end
  end

  defp grant(conn, server, :refresh_token, params, client, method) do
    with :ok <- refresh_enabled(server, method),
         :ok <- owner_loads(server, client, method),
         {:ok, previous} <- presented_refresh_token(server, params["refresh_token"], method),
         :ok <- issued_to(previous, client, method),
         :ok <- not_replayed(conn, server, client, previous, method),
         :ok <- refresh_unexpired(previous, method),
         {:ok, scopes} <-
           grant_scopes(
             params["scope"],
             [previous.scopes, client.scopes, Callbacks.scopes(server)],
             method
           ),
         :ok <- rotate(server, previous, method) do
      issue(server, client, scopes, method)
    end
  end

  defp for_client({:ok, issued, ttl}, client), do: {:ok, client, issued, ttl}

  defp for_client({:error, code, description, method}, client), do: {:error, code, description, method, client}

  defp owner_loads(server, client, method) do
    case Callbacks.load_owner(server, client.owner_id, client.company_id) do
      {:ok, _actor} -> :ok
      :error -> {:error, :invalid_client, "the client's owner may no longer use the API", method}
    end
  end

  defp grant_scopes(requested, lists, method) do
    case Scopes.grant(requested, Scopes.allowed(lists)) do
      {:ok, scopes} ->
        {:ok, scopes}

      {:error, :invalid_request} ->
        {:error, :invalid_request, "scope must be a space-delimited string", method}

      {:error, :invalid_scope} ->
        {:error, :invalid_scope, "the requested scope is not allowed for this client", method}
    end
  end

  defp refresh_enabled(server, method) do
    if Callbacks.issue_refresh_token?(server),
      do: :ok,
      else: {:error, :unauthorized_client, "the refresh_token grant is not enabled", method}
  end

  defp presented_refresh_token(server, refresh_token, method) when is_binary(refresh_token) and refresh_token != "" do
    case Lookup.fetch_by_refresh_token(server, refresh_token) do
      {:ok, previous} -> {:ok, previous}
      :error -> invalid_grant(method)
    end
  end

  defp presented_refresh_token(_server, _refresh_token, method),
    do: {:error, :invalid_request, "refresh_token is required", method}

  defp issued_to(%{client_id: id}, %{id: id}, _method), do: :ok
  defp issued_to(_previous, _client, method), do: invalid_grant(method)

  defp not_replayed(_conn, _server, _client, %{revoked_at: nil}, _method), do: :ok

  defp not_replayed(conn, server, client, %{revoked_at: revoked_at} = previous, method) do
    if DateTime.diff(DateTime.utc_now(), revoked_at, :millisecond) < @replay_grace_ms,
      do: invalid_grant(method),
      else: revoke_family(conn, server, client, previous, method)
  end

  defp revoke_family(conn, server, client, previous, method) do
    family =
      "client #{client.client_id} (owner #{previous.owner_id}, company #{previous.company_id})"

    revoked =
      server.access_token_resource().revoke_family(
        previous.client_id,
        previous.owner_id,
        previous.company_id,
        actor: ServerActor.new()
      )

    Telemetry.emit(
      [:token, :replayed],
      %{revoked: revoked_count(revoked)},
      %{
        client_id: client.client_id,
        owner_id: previous.owner_id,
        company_id: previous.company_id
      },
      conn,
      server
    )

    case revoked do
      {:ok, count} ->
        Logger.warning(
          "api_gatehouse: a revoked refresh token was presented again; revoked #{count} live token(s) of #{family}"
        )

        invalid_grant(method)

      {:error, error} ->
        Logger.error(
          "api_gatehouse: a revoked refresh token was presented again, but the tokens of #{family} " <>
            "could not be revoked: #{Exception.message(error)}"
        )

        {:error, :server_error, nil, method}
    end
  end

  defp revoked_count({:ok, count}), do: count
  defp revoked_count({:error, _error}), do: 0

  defp refresh_unexpired(%{refresh_expires_at: %DateTime{} = expires_at}, method) do
    if DateTime.after?(expires_at, DateTime.utc_now()), do: :ok, else: invalid_grant(method)
  end

  defp refresh_unexpired(_previous, method), do: invalid_grant(method)

  defp rotate(server, previous, method) do
    case server.access_token_resource().rotate(previous, actor: ServerActor.new()) do
      {:ok, _rotated} -> :ok
      {:error, _lost_the_race} -> invalid_grant(method)
    end
  end

  defp issue(server, client, scopes, method) do
    ttl = Callbacks.access_token_ttl(server)

    refresh_expires_in =
      if Callbacks.issue_refresh_token?(server), do: Callbacks.refresh_idle_ttl(server)

    attrs = %{
      client_id: client.id,
      owner_id: client.owner_id,
      company_id: client.company_id,
      scopes: scopes,
      expires_in: ttl,
      refresh_expires_in: refresh_expires_in
    }

    case server.access_token_resource().issue(attrs, actor: ServerActor.new()) do
      {:ok, issued} ->
        {:ok, issued, ttl}

      {:error, error} ->
        Logger.error("api_gatehouse: could not issue a token to client #{client.client_id}: #{Exception.message(error)}")

        {:error, :server_error, nil, method}
    end
  end

  defp respond(conn, %{__metadata__: metadata, scopes: scopes}, ttl) do
    body =
      Map.merge(
        %{
          access_token: metadata.access_token,
          token_type: "Bearer",
          expires_in: ttl,
          scope: Enum.join(scopes, " ")
        },
        if(metadata[:refresh_token], do: %{refresh_token: metadata.refresh_token}, else: %{})
      )

    Json.send_json(conn, 200, body)
  end

  defp invalid_grant(method),
    do: {:error, :invalid_grant, "the refresh token is invalid, expired, revoked or issued to another client", method}
end
