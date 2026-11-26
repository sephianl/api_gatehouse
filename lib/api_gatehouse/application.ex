defmodule ApiGatehouse.Application do
  @moduledoc """
  Starts the library's own rate-limit counter, `ApiGatehouse.RateLimiter`, so a
  host that mounts `ApiGatehouse.Plug.RateLimit` has nothing to supervise itself.

  It always starts, also when `config :api_gatehouse, :rate_limiter` names the
  host's own counter: the plug reads that setting per request, so the library's
  counter is there to fall back to and otherwise sits idle.

  Expired keys are swept every minute. Each key is one client address (or IPv6
  /64) per bucket and window, so a flood from many addresses holds memory for
  about a window plus a sweep — roughly two minutes at the default period —
  rather than piling up between rare sweeps.
  """
  use Application

  @impl Application
  @spec start(Application.start_type(), term()) :: Supervisor.on_start()
  def start(_type, _args) do
    children = [{ApiGatehouse.RateLimiter, clean_period: to_timeout(minute: 1)}]

    Supervisor.start_link(children, strategy: :one_for_one, name: ApiGatehouse.Supervisor)
  end
end
