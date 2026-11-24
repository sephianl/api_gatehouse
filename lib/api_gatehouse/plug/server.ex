defmodule ApiGatehouse.Plug.Server do
  @moduledoc """
  Names the host's `ApiGatehouse.Server` once per pipeline, so the library plugs
  after it — the route plugs included — need no `server:` option of their own.

      pipeline :api_oauth do
        plug ApiGatehouse.Plug.Server, server: MyAppWeb.ApiServer
        ...
      end

      post "/token", ApiGatehouse.Plug.Token, []

  Phoenix escapes a route's plug options into the router at compile time, so
  `server: MyAppWeb.ApiServer` on a route gives the router a compile-time
  dependency on the server module, and through it a compile-connected one on
  everything that module reaches: the resources and the owner lookup. `mix
  xref` then reports compile-connected cycles, and editing any of those files
  recompiles the router. Under `plug_init_mode: :runtime` (what Phoenix hosts
  set in dev and test) a pipeline plug's options are only a runtime reference,
  so the server is named here and read back from the connection. Prod's
  `:compile` mode makes it compile-time again, which only costs a one-off
  release build.

  A plug's own `server:` still takes precedence over this one. A library plug
  that finds neither raises `ArgumentError` per request; see
  `ApiGatehouse.Plug.Options.server/3`.
  """
  @behaviour Plug

  alias ApiGatehouse.Plug.Options

  @schema [server: [type: {:custom, Options, :validate_server, []}, required: true]]

  @impl Plug
  @spec init(keyword()) :: map()
  def init(opts), do: Options.validate(__MODULE__, @schema, opts)

  @impl Plug
  @spec call(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def call(conn, %{server: server}), do: Options.put_server(conn, server)
end
