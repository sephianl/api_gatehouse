defmodule ApiGatehouse.Plug.OAuthError do
  @moduledoc """
  Sends an RFC 6749 §5.2 error response: `{"error": ..., "error_description":
  ...}`, with 401 for `invalid_client`, 500 for `server_error` and 400 for every
  other code.

  An `invalid_client` for a client that tried HTTP Basic also carries a
  `WWW-Authenticate: Basic` challenge, which §5.2 requires.
  """

  import Plug.Conn

  alias ApiGatehouse.OAuth.ClientAuth
  alias ApiGatehouse.Plug.Json

  @basic_challenge ~s(Basic realm="oauth")

  @doc "Sends the error `code` with `description`, for a client that authenticated by `method`."
  @spec send_error(Plug.Conn.t(), atom(), String.t() | nil, ClientAuth.method()) :: Plug.Conn.t()
  def send_error(conn, code, description, method) do
    conn
    |> challenge(code, method)
    |> Json.send_json(status(code), body(code, description))
  end

  defp challenge(conn, :invalid_client, :basic), do: put_resp_header(conn, "www-authenticate", @basic_challenge)

  defp challenge(conn, _code, _method), do: conn

  defp status(:invalid_client), do: 401
  defp status(:server_error), do: 500
  defp status(_code), do: 400

  defp body(code, nil), do: %{error: Atom.to_string(code)}
  defp body(code, description), do: %{error: Atom.to_string(code), error_description: description}
end
