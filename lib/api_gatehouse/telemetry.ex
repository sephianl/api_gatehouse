defmodule ApiGatehouse.Telemetry do
  @moduledoc """
  Telemetry events for what happens at the endpoints reached before anyone is
  authenticated — the token and revocation endpoints and their rate limits — so
  a host can log security events, and trace an attack, under its own retention
  rules. The library logs none of this itself.

  Every event's measurements carry `:system_time` (`System.system_time/0`, in
  native units). Its metadata carries where the request came from:
  `:client_ip`, the address `ApiGatehouse.ClientIp.resolve/2` trusts, never an
  entry the caller wrote into a forwarding header; and `:user_agent`, the first
  `User-Agent` header cut to 200 bytes, or `nil`. No event carries a secret, a
  token or the connection, so a handler may log the metadata as it is.
  `:client_id` is always the client's public client id, not its row id.

  ## Events

    * `[:api_gatehouse, :token, :issued]` — the token endpoint issued a token.
      Metadata: `:grant_type` (`:client_credentials` or `:refresh_token`),
      `:client_id`, `:owner_id`, `:company_id`, `:scopes`.
    * `[:api_gatehouse, :token, :refused]` — the token endpoint answered an
      OAuth error. Metadata: `:grant_type` (`nil` for a missing or unsupported
      one, which is not echoed), `:error` (the RFC 6749 error code, an atom),
      `:description`, and `:client_id` once the client has authenticated, else
      `nil`.
    * `[:api_gatehouse, :token, :replayed]` — a refresh token revoked over five
      seconds earlier came back from its own client, so someone else holds it
      too, and the family's live tokens were revoked. Measurement `:revoked`,
      how many (0 when revoking them failed, which is also logged as an error).
      Metadata: `:client_id`, `:owner_id`, `:company_id`. The request's
      `:refused` event follows.
    * `[:api_gatehouse, :revocation, :accepted]` — an authenticated client
      asked to revoke a token. Metadata: `:client_id`, and `:revoked`, whether a
      live token of that client was revoked — which the RFC 7009 answer, a 200
      either way, does not say.
    * `[:api_gatehouse, :revocation, :refused]` — the revocation endpoint
      answered an OAuth error. Metadata: `:error`, `:description`, `:client_id`
      (`nil` unless the client authenticated).
    * `[:api_gatehouse, :rate_limit, :denied]` — `ApiGatehouse.Plug.RateLimit`
      turned a request away. Measurement `:retry_after_ms`. Metadata: `:bucket`,
      `:key` (the address, or IPv6 /64, counted), `:limit`, `:period`.

  ## Logging them

      :telemetry.attach_many(
        "my-app-api-security-log",
        ApiGatehouse.Telemetry.events(),
        &MyApp.ApiSecurityLog.handle_event/4,
        nil
      )

  A handler runs in the request's process, so it should be quick and must not
  raise: `:telemetry` detaches a handler that does.
  """

  alias ApiGatehouse.ClientIp
  alias ApiGatehouse.Server.Callbacks

  @user_agent_bytes 200

  @events [
    [:api_gatehouse, :token, :issued],
    [:api_gatehouse, :token, :refused],
    [:api_gatehouse, :token, :replayed],
    [:api_gatehouse, :revocation, :accepted],
    [:api_gatehouse, :revocation, :refused],
    [:api_gatehouse, :rate_limit, :denied]
  ]

  @doc "Every event the library emits, for `:telemetry.attach_many/4`."
  @spec events() :: [[atom()]]
  def events, do: @events

  @doc false
  @spec emit([atom()], map(), map(), Plug.Conn.t(), module()) :: :ok
  def emit(event, measurements, metadata, conn, server) do
    :telemetry.execute(
      [:api_gatehouse | event],
      Map.put(measurements, :system_time, System.system_time()),
      Map.merge(metadata, %{
        client_ip: ClientIp.resolve(conn, Callbacks.trusted_proxies(server)),
        user_agent: user_agent(conn)
      })
    )
  end

  defp user_agent(conn) do
    case Plug.Conn.get_req_header(conn, "user-agent") do
      [user_agent | _rest] ->
        binary_part(user_agent, 0, min(byte_size(user_agent), @user_agent_bytes))

      [] ->
        nil
    end
  end
end
