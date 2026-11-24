defmodule ApiGatehouse.Plug.NoStore do
  @moduledoc """
  Marks a response as uncacheable, for the endpoints that hand out or take
  credentials.

  RFC 6749 §5.1 requires it on token responses; the revocation response gets it
  for the same reason. The token and revocation plugs apply it themselves.
  """
  @behaviour Plug

  import Plug.Conn

  @impl Plug
  @spec init(keyword()) :: keyword()
  def init(opts), do: opts

  @impl Plug
  @spec call(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def call(conn, _opts) do
    conn
    |> put_resp_header("cache-control", "no-store")
    |> put_resp_header("pragma", "no-cache")
  end
end
