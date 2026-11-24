defmodule ApiGatehouse.Plug.RateLimitCounterTest do
  @moduledoc """
  Without a configured stub the plug counts with `ApiGatehouse.RateLimiter`,
  which the library's application starts. Not async: it removes the test stub
  from app env for its duration.

  The plug is initialised while the stub is still configured, so a plug that
  read the counter in `init/1` instead of per request would keep counting with
  the stub and never deny.
  """
  use ExUnit.Case, async: false

  import Plug.Test

  alias ApiGatehouse.Plug.RateLimit
  alias ApiGatehouse.Test.Server

  setup do
    opts =
      RateLimit.init(
        bucket: "counter-#{System.unique_integer([:positive])}",
        limit: 2,
        server: Server
      )

    stub = Application.fetch_env!(:api_gatehouse, :rate_limiter)
    Application.delete_env(:api_gatehouse, :rate_limiter)
    on_exit(fn -> Application.put_env(:api_gatehouse, :rate_limiter, stub) end)

    %{opts: opts}
  end

  test "the library's own counter allows up to the limit and then denies", %{opts: opts} do
    statuses =
      for _request <- 1..3, do: :post |> conn("/") |> RateLimit.call(opts) |> Map.get(:status)

    assert statuses == [nil, nil, 429]
  end

  test "each bucket counts on its own", %{opts: opts} do
    other =
      RateLimit.init(
        bucket: "other-#{System.unique_integer([:positive])}",
        limit: 2,
        server: Server
      )

    for _request <- 1..2, do: :post |> conn("/") |> RateLimit.call(opts)

    assert :post |> conn("/") |> RateLimit.call(other) |> Map.get(:status) == nil
  end
end
