defmodule ApiGatehouse.Plug.InitTest do
  @moduledoc """
  A production router compiles its pipeline plugs, running `init/1` once at
  build time. So `init/1` must only check literal options: it must not call the
  server module, which need not even be compiled yet.

  For a module that is not loaded, an optional callback silently resolves to its
  default instead of raising, so the unloaded module alone cannot show that
  `init/1` leaves the optional callbacks alone; a loaded probe server that
  reports every call can.
  """
  use ExUnit.Case, async: true

  alias ApiGatehouse.Plug.Bearer
  alias ApiGatehouse.Plug.NoStore
  alias ApiGatehouse.Plug.RateLimit
  alias ApiGatehouse.Plug.Revocation
  alias ApiGatehouse.Plug.Server
  alias ApiGatehouse.Plug.Token

  @not_compiled ApiGatehouse.Test.NotCompiledYet
  @plugs [Bearer, Revocation, Token, Server]

  defmodule ProbeServer do
    @moduledoc "A loaded host server that reports every callback the library makes to the calling process."
    @behaviour ApiGatehouse.Server

    @impl true
    def client_resource, do: called(:client_resource, ApiGatehouse.Test.Client)
    @impl true
    def access_token_resource, do: called(:access_token_resource, ApiGatehouse.Test.AccessToken)
    @impl true
    def load_owner(_owner_id, _company_id), do: called(:load_owner, {:error, :probe})
    @impl true
    def access_token_ttl, do: called(:access_token_ttl, 1)
    @impl true
    def refresh_idle_ttl, do: called(:refresh_idle_ttl, 1)
    @impl true
    def issue_refresh_token?, do: called(:issue_refresh_token?, false)
    @impl true
    def scopes, do: called(:scopes, [])
    @impl true
    def trusted_proxies, do: called(:trusted_proxies, [])

    defp called(name, value) do
      send(self(), {:server_called, name})
      value
    end
  end

  test "init never touches the server module" do
    for plug <- @plugs do
      assert %{server: @not_compiled} = plug.init(server: @not_compiled)
    end

    assert %{server: @not_compiled} = RateLimit.init(server: @not_compiled, bucket: "b", limit: 1)
    refute Code.ensure_loaded?(@not_compiled)
  end

  test "init calls no callback of a loaded server, optional ones included" do
    assert Code.ensure_loaded?(ProbeServer)

    for plug <- @plugs, do: plug.init(server: ProbeServer)
    RateLimit.init(server: ProbeServer, bucket: "b", limit: 1)

    refute_received {:server_called, _callback}
  end

  test "without server: init leaves the server to the connection" do
    for plug <- [Bearer, Revocation, Token] do
      refute Map.has_key?(plug.init([]), :server)
    end

    refute Map.has_key?(RateLimit.init(bucket: "b", limit: 1), :server)
  end

  test "init refuses a server: that is not a module, and options it does not know" do
    for plug <- @plugs, server <- [nil, "MyAppWeb.ApiServer", true, 42] do
      assert_raise ArgumentError, ~r/#{inspect(plug)}.*server/, fn ->
        plug.init(server: server)
      end
    end

    for plug <- [Bearer, Revocation, Token] do
      assert_raise ArgumentError, ~r/#{inspect(plug)}.*unknown options \[:realm\]/, fn ->
        plug.init(realm: "api")
      end
    end
  end

  test "NoStore marks a response uncacheable" do
    conn = :get |> Plug.Test.conn("/") |> NoStore.call(NoStore.init([]))

    assert Plug.Conn.get_resp_header(conn, "cache-control") == ["no-store"]
    assert Plug.Conn.get_resp_header(conn, "pragma") == ["no-cache"]
  end
end
