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
  checked with bcrypt. An unknown client id runs the same bcrypt work against
  nothing (`ApiGatehouse.OAuth.ClientSecret.verify/2`), so the answer's timing
  does not reveal which client ids exist. Every failure is the same
  `invalid_client`.

  Authentication says nothing about the client's owner: the token endpoint
  loads that separately.
  """

  import Plug.Conn

  alias ApiGatehouse.OAuth.ClientSecret
  alias ApiGatehouse.OAuth.Lookup

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
        if ClientSecret.verify(secret, client.client_secret_hash),
          do: {:ok, client, method},
          else: failed(method)

      :error ->
        false = ClientSecret.verify(secret, nil)
        failed(method)
    end
  end

  defp failed(method), do: {:error, :invalid_client, "client authentication failed", method}
end
