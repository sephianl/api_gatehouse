defmodule ApiGatehouse.ClientIp do
  @moduledoc """
  The address a request came from, safe to key a rate limit on.

  `conn.remote_ip` is the nearest hop — the host's ingress in production — so
  keying on it alone collapses every caller into one bucket. `X-Forwarded-For`
  carries the chain, but each proxy appends the address it received the request
  from, so the entries a caller wrote sit to the LEFT of the one our own ingress
  vouched for. Reading the left-most entry lets a caller mint a fresh bucket per
  request by forging the header, which defeats the limit entirely.

  So the client is resolved by trust, not by position. The socket peer is the
  right-most hop of the chain, after every `X-Forwarded-For` entry, and
  `RemoteIp` walks that chain from the right, returning the first address that
  is not a trusted proxy. A peer that is not a trusted proxy is therefore the
  client itself, and whatever `X-Forwarded-For` it sent is never read: a caller
  that reaches the host directly, past its ingress, cannot choose its bucket.

  The trusted set is the reserved/private ranges (loopback, `10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`, which `RemoteIp` always treats
  as proxies, as an in-cluster ingress usually sits there) plus whatever the host
  lists in `c:ApiGatehouse.Server.trusted_proxies/0`, such as its load balancer's
  ranges. Getting that set slightly wrong only ever over-collapses buckets — the
  walk can never reach a caller-forged entry, because a trusted ingress appended
  the real address to its right.

  That premise holds for `X-Forwarded-For` alone, so it is the only header read.
  `Forwarded`, `X-Client-Ip` and `X-Real-Ip` are passed through untouched by
  common ingresses; a caller that sends one after its own `X-Forwarded-For`
  would otherwise choose its own bucket.

  An IPv4 caller on a dual-stack listener shows up as an IPv4-mapped IPv6
  address (`::ffff:a.b.c.d`); it is read as the IPv4 address it is, both to
  match the trusted set and to key on.
  """

  import Bitwise

  @doc "The client address as a string, from `X-Forwarded-For` by trust, else the socket peer."
  @spec resolve(Plug.Conn.t(), [String.t()]) :: String.t()
  def resolve(conn, trusted_proxies), do: conn |> client(trusted_proxies) |> format()

  @doc """
  The client's rate-limit key: its IPv4 address, or the /64 its IPv6 address is
  in (as `"2001:db8:1:2::/64"`).

  One host or one LAN is routinely handed a whole /64, and an IPv6 caller can
  send each request from a fresh address in it; keyed per address, it would get
  2^64 buckets.
  """
  @spec rate_limit_key(Plug.Conn.t(), [String.t()]) :: String.t()
  def rate_limit_key(conn, trusted_proxies) do
    case client(conn, trusted_proxies) do
      {a, b, c, d, _e, _f, _g, _h} -> format({a, b, c, d, 0, 0, 0, 0}) <> "/64"
      ipv4 -> format(ipv4)
    end
  end

  defp client(conn, trusted_proxies) do
    peer = ipv4_if_mapped(conn.remote_ip)

    if proxy?(peer, trusted_proxies) do
      conn.req_headers
      |> forwarded_client(trusted_proxies)
      |> Kernel.||(peer)
      |> ipv4_if_mapped()
    else
      peer
    end
  end

  defp forwarded_client(headers, trusted_proxies),
    do: RemoteIp.from(headers, headers: ["x-forwarded-for"], proxies: trusted_proxies)

  # By RemoteIp's own reckoning — listed, or private/loopback — a chain of the
  # peer alone holds no client exactly when the peer is a proxy.
  defp proxy?(peer, trusted_proxies), do: forwarded_client([{"x-forwarded-for", format(peer)}], trusted_proxies) == nil

  defp ipv4_if_mapped({0, 0, 0, 0, 0, 0xFFFF, high, low}), do: {high >>> 8, high &&& 0xFF, low >>> 8, low &&& 0xFF}

  defp ipv4_if_mapped(address), do: address

  defp format(address), do: address |> :inet.ntoa() |> to_string()
end
