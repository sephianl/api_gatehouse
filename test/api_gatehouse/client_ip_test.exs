defmodule ApiGatehouse.ClientIpTest do
  @moduledoc """
  The rate-limit key has to be an address the caller cannot choose: the client
  is the right-most `X-Forwarded-For` entry that is not a trusted proxy, the
  header is believed only when the socket peer is itself a trusted proxy, no
  other forwarding header is believed, and an IPv6 caller is keyed by the /64
  it holds rather than by each of its addresses.
  """
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias ApiGatehouse.ClientIp

  @trusted ["35.191.0.0/16", "130.211.0.0/22"]

  defp resolve(headers, trusted \\ @trusted) do
    headers
    |> Enum.reduce(conn(:get, "/"), fn {name, value}, acc -> put_req_header(acc, name, value) end)
    |> ClientIp.resolve(trusted)
  end

  defp from_peer(peer, xff \\ nil) do
    conn = Map.put(conn(:get, "/"), :remote_ip, peer)
    if xff, do: put_req_header(conn, "x-forwarded-for", xff), else: conn
  end

  # ::ffff:a.b.c.d, as a dual-stack listener reports an IPv4 caller.
  defp mapped({a, b, c, d}), do: {0, 0, 0, 0, 0, 0xFFFF, a * 256 + b, c * 256 + d}

  test "without a forwarding header the socket peer is the client" do
    assert resolve([]) == "127.0.0.1"

    assert :get |> conn("/") |> Map.put(:remote_ip, {198, 51, 100, 4}) |> ClientIp.resolve([]) ==
             "198.51.100.4"
  end

  test "the address our ingress appended wins over one the caller wrote" do
    assert resolve([{"x-forwarded-for", "6.6.6.6, 203.0.113.7"}]) == "203.0.113.7"
  end

  test "trusted proxies are walked past from the right" do
    assert resolve([{"x-forwarded-for", "203.0.113.7, 130.211.0.9, 35.191.0.5"}]) == "203.0.113.7"
  end

  test "an untrusted proxy over-collapses rather than reaching a forged entry" do
    assert resolve([{"x-forwarded-for", "6.6.6.6, 203.0.113.7, 35.191.0.5"}], []) == "35.191.0.5"
  end

  test "private hops are skipped even with no proxies configured" do
    assert resolve([{"x-forwarded-for", "203.0.113.7, 10.0.0.12"}], []) == "203.0.113.7"
  end

  test "forged x-real-ip, x-client-ip and forwarded headers after XFF are ignored" do
    xff = {"x-forwarded-for", "203.0.113.7, 35.191.0.5"}

    for forged <- [
          {"x-real-ip", "6.6.6.6"},
          {"x-client-ip", "7.7.7.7"},
          {"forwarded", "for=8.8.4.4"},
          {"x-real-ip", "2001:db8::1"}
        ] do
      assert resolve([xff, forged]) == "203.0.113.7", "#{inspect(forged)} chose the bucket"
    end
  end

  test "forwarding headers other than XFF are never read on their own" do
    assert resolve([{"x-real-ip", "6.6.6.6"}, {"forwarded", "for=8.8.4.4"}]) == "127.0.0.1"
  end

  test "IPv6 clients resolve" do
    assert resolve([{"x-forwarded-for", "2001:db8::1, 35.191.0.5"}]) == "2001:db8::1"
  end

  describe "X-Forwarded-For is believed only from a trusted peer" do
    test "a caller connecting directly cannot choose its address by sending the header" do
      for forged <- ["6.6.6.6", "6.6.6.6, 7.7.7.7", "2001:db8::666"] do
        assert {198, 51, 100, 4} |> from_peer(forged) |> ClientIp.resolve(@trusted) ==
                 "198.51.100.4"
      end
    end

    test "a configured proxy's chain is walked" do
      assert {35, 191, 0, 5} |> from_peer("6.6.6.6, 203.0.113.7") |> ClientIp.resolve(@trusted) ==
               "203.0.113.7"
    end

    test "a private-range or loopback peer, such as an in-cluster ingress, counts as a proxy" do
      assert {10, 0, 0, 12} |> from_peer("203.0.113.7") |> ClientIp.resolve([]) == "203.0.113.7"
      assert {127, 0, 0, 1} |> from_peer("203.0.113.7") |> ClientIp.resolve([]) == "203.0.113.7"
    end

    test "an IPv4-mapped peer is judged by its IPv4 address" do
      assert {35, 191, 0, 5} |> mapped() |> from_peer("203.0.113.7") |> ClientIp.resolve(@trusted) ==
               "203.0.113.7"

      assert {198, 51, 100, 4} |> mapped() |> from_peer("6.6.6.6") |> ClientIp.resolve(@trusted) ==
               "198.51.100.4"
    end
  end

  describe "rate_limit_key/2" do
    test "an IPv4 caller is keyed by its address" do
      assert {198, 51, 100, 4} |> from_peer() |> ClientIp.rate_limit_key(@trusted) ==
               "198.51.100.4"
    end

    test "an IPv6 caller is keyed by its /64, so rotating through its own block buys nothing" do
      keys =
        for xff <- ["2001:db8:1:2::1", "2001:db8:1:2:ffff:ffff:ffff:fffe", "2001:db8:1:2:abcd::9"] do
          {35, 191, 0, 5} |> from_peer(xff) |> ClientIp.rate_limit_key(@trusted)
        end

      assert Enum.uniq(keys) == ["2001:db8:1:2::/64"]

      assert {35, 191, 0, 5} |> from_peer("2001:db8:1:3::1") |> ClientIp.rate_limit_key(@trusted) ==
               "2001:db8:1:3::/64"
    end

    test "a direct IPv6 peer is keyed by its /64 too" do
      assert {0x2001, 0xDB8, 0, 7, 1, 2, 3, 4} |> from_peer() |> ClientIp.rate_limit_key(@trusted) ==
               "2001:db8:0:7::/64"
    end

    test "IPv4-mapped callers keep their own IPv4 key rather than sharing ::/64" do
      assert {198, 51, 100, 4} |> mapped() |> from_peer() |> ClientIp.rate_limit_key(@trusted) ==
               "198.51.100.4"

      assert {198, 51, 100, 5} |> mapped() |> from_peer() |> ClientIp.rate_limit_key(@trusted) ==
               "198.51.100.5"
    end
  end
end
