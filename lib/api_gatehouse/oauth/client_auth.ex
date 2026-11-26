defmodule ApiGatehouse.OAuth.ClientAuth do
  @moduledoc """
  Authenticates the client calling the token or revocation endpoint (RFC 6749
  §2.3.1), by `client_secret_basic` — HTTP Basic with the form-encoded client id
  and secret — or `client_secret_post` — `client_id` and `client_secret` in the
  request body.

  Only the request body is read, never the query string: a secret in a URL ends
  up in access logs. A request using both methods is an `invalid_request`
  (RFC 6749 §2.3), as is a body `client_id` that differs from the Basic one; a
  body carrying only the same `client_id` as the Basic header is accepted, as
  some clients send it.

  The client is looked up among the live (not deleted) clients, and its secret
  checked against its SHA-256 hash (`ApiGatehouse.OAuth.ClientSecret`). An
  unknown client id runs the same check against a dummy, so the answer's timing
  does not reveal which client ids exist. Every failure is the same
  `invalid_client`.

  A client still on a bcrypt hash — created by api_gatehouse 0.1.0, or brought
  over from another server — is re-encoded as SHA-256 the first time its secret
  verifies (`:upgrade_secret_hash`), so a flood naming its client id costs
  bcrypt work only until it is next used. Should that write fail, the client
  is authenticated all the same and keeps its bcrypt hash.

  Authentication says nothing about the client's owner: the token endpoint
  loads that separately.
  """

  import Plug.Conn

  alias ApiGatehouse.OAuth.ClientSecret
  alias ApiGatehouse.OAuth.Lookup
  alias ApiGatehouse.OAuth.ServerActor
  alias Ash.Error.Changes.StaleRecord

  require Logger

  @typedoc "How the client authenticated, which decides the `invalid_client` challenge."
  @type method :: :basic | :post | :none

  @typedoc "An OAuth error: its code, a description, and how the client tried to authenticate."
  @type error :: {:error, atom(), String.t(), method()}

  @doc "The live client the request authenticates as, and how it did."
  @spec authenticate(Plug.Conn.t(), module()) :: {:ok, struct(), method()} | error()
  def authenticate(conn, server) do
    case credentials(conn) do
      {:ok, method, client_id, secret} -> verify(server, method, client_id, secret)
      {:error, _code, _description, _method} = error -> error
    end
  end

  @doc "The request's body parameters, or none when the body was not parsed."
  @spec body_params(Plug.Conn.t()) :: map()
  def body_params(%Plug.Conn{body_params: %{} = params}) when not is_struct(params), do: params
  def body_params(_conn), do: %{}

  defp credentials(conn) do
    params = body_params(conn)

    case basic_credentials(conn) do
      {:ok, client_id, secret} -> basic_only(params, client_id, secret)
      :malformed -> {:error, :invalid_client, "the Basic credentials are malformed", :basic}
      :absent -> posted(params)
    end
  end

  defp basic_only(%{"client_secret" => _secret}, _client_id, _basic_secret),
    do: {:error, :invalid_request, "use only one client authentication method", :basic}

  defp basic_only(%{"client_id" => posted}, client_id, _secret) when posted != client_id,
    do: {:error, :invalid_request, "client_id does not match the Basic credentials", :basic}

  defp basic_only(_params, client_id, secret), do: {:ok, :basic, client_id, secret}

  defp posted(%{"client_id" => client_id, "client_secret" => secret})
       when is_binary(client_id) and is_binary(secret) and client_id != "", do: {:ok, :post, client_id, secret}

  defp posted(_params), do: {:error, :invalid_client, "client authentication is required", :none}

  defp basic_credentials(conn) do
    case get_req_header(conn, "authorization") do
      [header | _rest] -> parse_authorization(header)
      [] -> :absent
    end
  end

  defp parse_authorization(header) do
    case String.split(header, " ", parts: 2) do
      [scheme, encoded] ->
        if String.downcase(scheme) == "basic",
          do: decode_basic(String.trim(encoded)),
          else: :absent

      [_scheme] ->
        :absent
    end
  end

  defp decode_basic(encoded) do
    with {:ok, decoded} <- Base.decode64(encoded, padding: false),
         [client_id, secret] <- :binary.split(decoded, ":"),
         {:ok, client_id} when client_id != "" <- form_decode(client_id),
         {:ok, secret} <- form_decode(secret) do
      {:ok, client_id, secret}
    else
      _malformed -> :malformed
    end
  end

  defp form_decode(value) do
    {:ok, URI.decode_www_form(value)}
  rescue
    ArgumentError -> :error
  end

  defp verify(server, method, client_id, secret) do
    case Lookup.fetch_client(server, client_id) do
      {:ok, client} ->
        if ClientSecret.verify(secret, client.client_secret_hash) do
          upgrade_secret_hash(server, client, secret)
          {:ok, client, method}
        else
          failed(method)
        end

      :error ->
        false = ClientSecret.verify(secret, nil)
        failed(method)
    end
  end

  defp upgrade_secret_hash(server, client, secret) do
    if ClientSecret.upgrade?(secret, client.client_secret_hash) do
      client
      |> server.client_resource().upgrade_secret_hash(secret,
        actor: ServerActor.new(),
        tenant: client.company_id
      )
      |> upgraded(client)
    end
  end

  defp upgraded({:ok, _client}, _client_before), do: :ok

  defp upgraded({:error, error}, client) do
    # Stale: a concurrent request upgraded it first, or the secret changed since it was read.
    if !Enum.any?(Map.get(error, :errors, []), &match?(%StaleRecord{}, &1)) do
      Logger.warning(
        "api_gatehouse: client #{client.client_id} keeps its bcrypt secret hash, as it could not be " <>
          "re-encoded: #{Exception.message(error)}"
      )
    end

    :ok
  end

  defp failed(method), do: {:error, :invalid_client, "client authentication failed", method}
end
