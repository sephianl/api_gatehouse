defmodule ApiGatehouse.Plug.RateLimitTest do
  @moduledoc """
  Each plug instance counts against its own bucket, keyed by the trusted client
  address, and a denied request is a JSON 429 with a `Retry-After`. The counter
  is the configured stub here; `RateLimitCounterTest` runs the real one.
  """
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias ApiGatehouse.Plug.RateLimit
  alias ApiGatehouse.Test.Flow
  alias ApiGatehouse.Test.Server
  alias ApiGatehouse.Test.User

  defp limit(conn, opts), do: RateLimit.call(conn, RateLimit.init(Keyword.put_new(opts, :server, Server)))

  test "counts by client address in the plug's bucket" do
    conn = limit(conn(:post, "/"), bucket: "api_oauth_token", limit: 20)

    refute conn.halted
    assert_received {:rate_limit_hit, "api_oauth_token:127.0.0.1", 60_000, 20}
  end

  test "passes the period through" do
    limit(conn(:post, "/"), bucket: "api_oauth_revoke", limit: 5, period: 1_000)

    assert_received {:rate_limit_hit, "api_oauth_revoke:127.0.0.1", 1_000, 5}
  end

  test "keys on the forwarded client behind the server's trusted proxies" do
    :post
    |> conn("/")
    |> put_req_header("x-forwarded-for", "203.0.113.7, 35.191.0.5")
    |> limit(bucket: "api_oauth_token", limit: 20)

    assert_received {:rate_limit_hit, "api_oauth_token:203.0.113.7", _period, _limit}
  end

  test "a denied request is a halted JSON 429 with a Retry-After in seconds" do
    conn = limit(conn(:post, "/"), bucket: "denied", limit: 1)

    assert conn.halted
    assert conn.status == 429
    assert Flow.json(conn) == %{"error" => "rate_limited"}
    assert get_resp_header(conn, "retry-after") == ["2"]
  end

  test "the token and revocation routes count against their own buckets" do
    %{client_id: client_id, secret: secret} = Flow.create_client(User.admin())

    Flow.token_basic(client_id, secret)
    Flow.revoke(client_id, secret, %{"token" => "never-issued"})
    Flow.api(:get, "/whoami", nil)

    assert_received {:rate_limit_hit, "api_oauth_token:127.0.0.1", 60_000, 20}
    assert_received {:rate_limit_hit, "api_oauth_revoke:127.0.0.1", 60_000, 30}
    refute_received {:rate_limit_hit, _key, _period, _limit}
  end

  test "init validates its options" do
    assert %{period: 60_000, bucket: "b", limit: 1} =
             RateLimit.init(bucket: "b", limit: 1, server: Server)

    assert_raise ArgumentError, ~r/bucket/, fn -> RateLimit.init(limit: 1) end
    assert_raise ArgumentError, ~r/bucket/, fn -> RateLimit.init(bucket: :token, limit: 1) end
    assert_raise ArgumentError, ~r/limit/, fn -> RateLimit.init(bucket: "b") end
    assert_raise ArgumentError, ~r/limit/, fn -> RateLimit.init(bucket: "b", limit: 0) end

    assert_raise ArgumentError, ~r/period/, fn ->
      RateLimit.init(bucket: "b", limit: 1, period: -1)
    end

    assert_raise ArgumentError, ~r/server/, fn ->
      RateLimit.init(bucket: "b", limit: 1, server: "Api")
    end

    assert_raise ArgumentError, ~r/key/, fn ->
      RateLimit.init(bucket: "b", limit: 1, key: :actor)
    end
  end
end
