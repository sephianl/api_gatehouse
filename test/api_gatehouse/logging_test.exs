defmodule ApiGatehouse.LoggingTest do
  @moduledoc """
  No token or secret value reaches the log, at any level, on any path: issuing,
  refusing, refreshing, replaying (which logs a warning), revoking,
  authenticating, and failing with a server error (which logs an error).

  The host's router is configured as the README asks, with `secret` among
  Phoenix's `:filter_parameters`. Hashes are not checked: a data layer's debug
  log shows the values it writes and looks up, and a hash is not a credential.

  Not async: it lowers the global logger level to debug for its duration.
  """
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias ApiGatehouse.Test.Client
  alias ApiGatehouse.Test.FailingServer
  alias ApiGatehouse.Test.Flow
  alias ApiGatehouse.Test.User

  setup do
    level = Logger.level()
    Logger.configure(level: :debug)
    on_exit(fn -> Logger.configure(level: level) end)
  end

  test "secrets and tokens never appear in the log" do
    user = User.admin()

    {secrets, log} =
      with_log([level: :debug], fn ->
        %{client: client, client_id: client_id, secret: secret} =
          Flow.create_client(user, %{scopes: ["read", "write"]})

        basic = client_id |> Flow.token_basic(secret) |> Flow.json()
        posted = client_id |> Flow.token_post(secret) |> Flow.json()
        Flow.token_basic(client_id, secret <> "x")
        Flow.token_post(client_id, String.reverse(secret))
        Flow.token_basic("not-#{client_id}", secret)

        Flow.token_basic(client_id, secret, %{
          "grant_type" => "client_credentials",
          "client_secret" => secret
        })

        rotated = client_id |> Flow.refresh(secret, basic["refresh_token"]) |> Flow.json()
        Flow.refresh(client_id, secret, basic["refresh_token"])
        basic["refresh_token"] |> Flow.row_for_refresh() |> Flow.backdate(:revoked_at, 10)
        Flow.refresh(client_id, secret, basic["refresh_token"])
        Flow.refresh(client_id, "wrong", posted["refresh_token"])

        fresh = client_id |> Flow.token_basic(secret) |> Flow.json()
        fresh["refresh_token"] |> Flow.row_for_refresh() |> Flow.backdate(:revoked_at, 10)

        Flow.token_through(
          FailingServer,
          %{"grant_type" => "refresh_token", "refresh_token" => fresh["refresh_token"]},
          [{"authorization", Flow.basic(client_id, secret)}]
        )

        Flow.token_through(FailingServer, %{"grant_type" => "client_credentials"}, [
          {"authorization", Flow.basic(client_id, secret)}
        ])

        last = client_id |> Flow.token_basic(secret) |> Flow.json()
        Flow.api(:get, "/whoami", last["access_token"])
        Flow.api(:get, "/whoami", last["refresh_token"])
        Flow.revoke(client_id, secret, %{"token" => last["access_token"]})
        Flow.revoke(client_id, "wrong", %{"token" => last["refresh_token"]})
        Flow.revoke(client_id, secret, %{"token" => "never-issued-#{secret}"})
        Flow.api(:get, "/whoami", last["access_token"])

        {:ok, _deleted} = Client.soft_delete(client, actor: user, tenant: user.company_id)
        Flow.token_basic(client_id, secret)

        tokens =
          Enum.flat_map(
            [basic, posted, rotated, fresh, last],
            &[&1["access_token"], &1["refresh_token"]]
          )

        [secret | tokens]
      end)

    assert log =~ "presented again"
    assert log =~ "could not issue a token"

    for secret <- secrets, is_binary(secret) do
      refute log =~ secret
    end
  end
end
