defmodule ApiGatehouse.Plug.Revocation do
  @moduledoc """
  RFC 7009 token revocation, for the client a token was issued to.

      post "/api/oauth/revoke", ApiGatehouse.Plug.Revocation, []

  in a scope piped through a pipeline that starts with `ApiGatehouse.Plug.Server`.

  The client authenticates exactly as at the token endpoint
  (`ApiGatehouse.OAuth.ClientAuth`); a failure is a 401 `invalid_client`, and a
  missing `token` an `invalid_request`. The owner is not loaded: revoking is
  always safe, also for a client whose owner lost access.

  `token` may be an access token or a refresh token. `token_type_hint`
  (`access_token` or `refresh_token`) only decides which is looked up first.
  Either revokes the row holding both, so revoking a refresh token also stops
  its access token, and the other way round (§2.1).

  Otherwise the answer is a 200 with an empty body, whatever happened —
  including for a token that never existed, was already revoked, or belongs to
  another client, which is left alone. The spec requires it, and it keeps the
  endpoint from telling a caller which of its guesses are real tokens. Nothing
  about the token is logged; whether one was revoked is reported only to the
  host, as `ApiGatehouse.Telemetry` events. The response is marked `no-store`.
  """
  @behaviour Plug

  import Plug.Conn

  alias ApiGatehouse.OAuth.ClientAuth
  alias ApiGatehouse.OAuth.Lookup
  alias ApiGatehouse.OAuth.ServerActor
  alias ApiGatehouse.Plug.NoStore
  alias ApiGatehouse.Plug.OAuthError
  alias ApiGatehouse.Plug.Options
  alias ApiGatehouse.Telemetry

  @impl Plug
  @spec init(keyword()) :: map()
  def init(opts), do: Options.validate(__MODULE__, opts)

  @impl Plug
  @spec call(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def call(conn, opts) do
    server = Options.server(conn, __MODULE__, opts)
    conn = NoStore.call(conn, [])
    params = ClientAuth.body_params(conn)

    with {:ok, client, method} <- ClientAuth.authenticate(conn, server),
         {:ok, token} <- presented_token(params, client, method) do
      revoked = revoke(server, client, token, params["token_type_hint"])

      Telemetry.emit(
        [:revocation, :accepted],
        %{},
        %{client_id: client.client_id, revoked: revoked},
        conn,
        server
      )

      send_resp(conn, 200, "")
    else
      {:error, code, description, method} ->
        refuse(conn, server, code, description, method, nil)

      {:error, code, description, method, client} ->
        refuse(conn, server, code, description, method, client)
    end
  end

  defp presented_token(%{"token" => token}, _client, _method) when is_binary(token) and token != "", do: {:ok, token}

  defp presented_token(_params, client, method), do: {:error, :invalid_request, "token is required", method, client}

  defp refuse(conn, server, code, description, method, client) do
    Telemetry.emit(
      [:revocation, :refused],
      %{},
      %{error: code, description: description, client_id: client && client.client_id},
      conn,
      server
    )

    OAuthError.send_error(conn, code, description, method)
  end

  defp revoke(server, client, token, hint) do
    with {:ok, row} <- find(server, token, hint),
         true <- row.client_id == client.id and is_nil(row.revoked_at),
         {:ok, _revoked} <- server.access_token_resource().revoke(row, actor: ServerActor.new()) do
      true
    else
      _not_revoked -> false
    end
  end

  defp find(server, token, "refresh_token") do
    with :error <- Lookup.fetch_by_refresh_token(server, token),
         do: Lookup.fetch_by_access_token(server, token)
  end

  defp find(server, token, _access_token_or_no_hint) do
    with :error <- Lookup.fetch_by_access_token(server, token),
         do: Lookup.fetch_by_refresh_token(server, token)
  end
end
