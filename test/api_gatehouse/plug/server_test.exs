defmodule ApiGatehouse.Plug.ServerTest do
  @moduledoc """
  A host names its server once, with `ApiGatehouse.Plug.Server` at the top of a
  pipeline, so no route's options give its router a compile-time reference to
  it. Every library plug then finds the server on the connection, still prefers
  its own `server:`, and refuses to run with neither — `Bearer` above all, which
  must never let an unconfigured request through.
  """
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias ApiGatehouse.Plug.Bearer
  alias ApiGatehouse.Plug.RateLimit
  alias ApiGatehouse.Plug.Revocation
  alias ApiGatehouse.Plug.Server
  alias ApiGatehouse.Plug.Token
  alias ApiGatehouse.Test.ConfiguredServer
  alias ApiGatehouse.Test.Flow
  alias ApiGatehouse.Test.User

  defmodule UnconfiguredApiPipeline do
    @moduledoc "An API pipeline missing `ApiGatehouse.Plug.Server`, reporting whether a request got past `Bearer`."
    use Plug.Builder

    plug Bearer
    plug :reached

    defp reached(conn, _opts) do
      send(self(), :reached_past_bearer)
      conn
    end
  end

  defp on_server(conn, server), do: Server.call(conn, Server.init(server: server))

  test "puts the server on the connection" do
    conn = :get |> conn("/") |> on_server(ConfiguredServer)

    assert conn.private.api_gatehouse_server == ConfiguredServer
  end

  test "requires a module" do
    assert_raise ArgumentError, ~r/ApiGatehouse.Plug.Server.*server/, fn -> Server.init([]) end
    assert_raise ArgumentError, ~r/expected a module/, fn -> Server.init(server: nil) end

    assert_raise ArgumentError, ~r/expected a module/, fn ->
      Server.init(server: "MyAppWeb.ApiServer")
    end
  end

  test "the plugs after it run on the connection's server" do
    %{client_id: client_id, secret: secret} =
      Flow.create_client(User.admin(), %{scopes: ["read", "write"]})

    conn =
      :post
      |> conn("/", %{"grant_type" => "client_credentials"})
      |> put_req_header("authorization", Flow.basic(client_id, secret))
      |> on_server(ConfiguredServer)
      |> Token.call(Token.init([]))

    assert %{"scope" => "read", "expires_in" => 600} = Flow.json(conn)

    :post
    |> conn("/")
    |> put_req_header("x-forwarded-for", "203.0.113.7, 130.211.0.9")
    |> on_server(ConfiguredServer)
    |> RateLimit.call(RateLimit.init(bucket: "b", limit: 1))

    assert_received {:rate_limit_hit, "b:203.0.113.7", _period, _limit}
  end

  test "a plug's own server: wins over the connection's" do
    %{client_id: client_id, secret: secret} =
      Flow.create_client(User.admin(), %{scopes: ["read", "write"]})

    conn =
      :post
      |> conn("/", %{"grant_type" => "client_credentials"})
      |> put_req_header("authorization", Flow.basic(client_id, secret))
      |> on_server(ConfiguredServer)
      |> Token.call(Token.init(server: ApiGatehouse.Test.Server))

    assert %{"scope" => "read write", "expires_in" => 3600} = Flow.json(conn)
  end

  test "every plug raises without a server" do
    for {plug, opts} <- [
          {Token, []},
          {Revocation, []},
          {Bearer, []},
          {RateLimit, [bucket: "b", limit: 1]}
        ] do
      assert_raise ArgumentError, ~r/#{inspect(plug)} has no API server/, fn ->
        :post |> conn("/") |> plug.call(plug.init(opts))
      end
    end
  end

  test "Bearer never lets a request through a pipeline without a server" do
    assert_raise ArgumentError, fn ->
      :get
      |> conn("/")
      |> put_req_header("authorization", "Bearer anything")
      |> UnconfiguredApiPipeline.call(UnconfiguredApiPipeline.init([]))
    end

    refute_received :reached_past_bearer
  end
end
