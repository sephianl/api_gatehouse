defmodule ApiGatehouse.Plug.RateLimit do
  @moduledoc """
  A per-address ceiling on requests to one endpoint, for the token and
  revocation endpoints, which are reached before anyone is authenticated.

      plug ApiGatehouse.Plug.RateLimit, bucket: "api_oauth_token", limit: 20

  after `ApiGatehouse.Plug.Server` in the pipeline, or with its own
  `server: MyAppWeb.ApiServer`, which supplies the trusted proxies.

  Options:

    * `:bucket` (required) — the counter's name. Each plug instance passes its
      own, so one endpoint cannot eat another's budget.
    * `:limit` (required) — requests allowed per period.
    * `:period` — the period in milliseconds; defaults to 60 000.

  Requests are counted by `ApiGatehouse.ClientIp` — an unauthenticated flood has
  no other identity. The counter is `ApiGatehouse.RateLimiter` unless `config
  :api_gatehouse, :rate_limiter` names another module with Hammer's `hit/3`,
  read per request so a test stub can stand in. A denied request gets a halted
  429 `{"error":"rate_limited"}` with a `Retry-After` in seconds.
  """
  @behaviour Plug

  import Plug.Conn

  alias ApiGatehouse.ClientIp
  alias ApiGatehouse.Plug.Json
  alias ApiGatehouse.Plug.Options
  alias ApiGatehouse.Server.Callbacks

  @schema [
    bucket: [type: :string, required: true],
    limit: [type: :pos_integer, required: true],
    period: [type: :pos_integer, default: 60_000]
  ]

  @impl Plug
  @spec init(keyword()) :: map()
  def init(opts), do: Options.validate(__MODULE__, @schema, opts)

  @impl Plug
  @spec call(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def call(conn, %{bucket: bucket, limit: limit, period: period} = opts) do
    server = Options.server(conn, __MODULE__, opts)
    counter = Application.get_env(:api_gatehouse, :rate_limiter, ApiGatehouse.RateLimiter)

    "#{bucket}:#{ClientIp.resolve(conn, Callbacks.trusted_proxies(server))}"
    |> counter.hit(period, limit)
    |> allow(conn)
  end

  defp allow({:allow, _count}, conn), do: conn

  defp allow({:deny, retry_after_ms}, conn) do
    conn
    |> put_resp_header("retry-after", Integer.to_string(max(div(retry_after_ms + 999, 1000), 1)))
    |> Json.send_json(429, %{error: "rate_limited"})
    |> halt()
  end
end
