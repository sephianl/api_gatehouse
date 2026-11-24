defmodule ApiGatehouse.Test.RateLimiterStub do
  @moduledoc """
  Stands in for the Hammer counter in tests, configured as `config
  :api_gatehouse, :rate_limiter`.

  Reports each hit to the calling process — under `Plug.Test` the plug runs in
  the test process — and denies every key in the `denied` bucket, so a test
  picks the outcome by picking a bucket instead of mutating app env.
  """

  @spec hit(String.t(), pos_integer(), pos_integer()) :: {:allow, 1} | {:deny, pos_integer()}
  def hit(key, period, limit) do
    send(self(), {:rate_limit_hit, key, period, limit})

    if String.starts_with?(key, "denied:"), do: {:deny, 1_500}, else: {:allow, 1}
  end
end
