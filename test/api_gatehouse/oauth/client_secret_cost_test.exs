defmodule ApiGatehouse.OAuth.ClientSecretCostTest do
  @moduledoc """
  The token and revocation endpoints are reached before anyone is
  authenticated, so what one request costs there is what a flood costs. At
  bcrypt's production cost (12 rounds, over 100 ms of CPU per check) a few
  hundred requests a second saturate any machine, so neither an unknown client
  id nor a client's own secret may cost bcrypt work: ten requests have to fit
  in less time than two bcrypt checks.

  Not async: it raises bcrypt's cost in app env for its duration.
  """
  use ExUnit.Case, async: false

  alias ApiGatehouse.Test.Flow
  alias ApiGatehouse.Test.User

  @ten_requests_ms 200

  setup do
    previous = Application.fetch_env!(:bcrypt_elixir, :log_rounds)
    Application.put_env(:bcrypt_elixir, :log_rounds, 12)
    on_exit(fn -> Application.put_env(:bcrypt_elixir, :log_rounds, previous) end)
  end

  defp elapsed_ms(fun), do: fun |> :timer.tc() |> elem(0) |> div(1000)

  test "an unknown client id costs no bcrypt work" do
    Flow.token_basic("warm-up", "x")

    elapsed =
      elapsed_ms(fn ->
        for n <- 1..10, do: assert(Flow.token_basic("never-registered-#{n}", "x").status == 401)
      end)

    assert elapsed < @ten_requests_ms, "10 unknown-client requests took #{elapsed} ms"
  end

  test "a client's own secret, right or wrong, costs no bcrypt work" do
    %{client_id: client_id, secret: secret} = Flow.create_client(User.admin())
    Flow.token_basic(client_id, "warm-up")

    elapsed =
      elapsed_ms(fn ->
        for _pair <- 1..5 do
          assert Flow.token_basic(client_id, secret).status == 200
          assert Flow.token_basic(client_id, "wrong").status == 401
        end
      end)

    assert elapsed < @ten_requests_ms, "10 known-client requests took #{elapsed} ms"
  end
end
