defmodule ApiGatehouse.RateLimiter do
  @moduledoc """
  Hammer counter behind `ApiGatehouse.Plug.RateLimit`, separate from any counter
  the host keeps for its other endpoints.

  Counts per node: the ETS backend is not shared across a cluster.
  """
  use Hammer, backend: :ets
end
