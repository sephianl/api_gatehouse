defmodule ApiGatehouse.TelemetryTest do
  @moduledoc """
  The endpoints reached before anyone is authenticated report what happened as
  telemetry events, with the address the request came from, so a host can log
  security events and trace an attack. A handler must be able to log every
  field as it is: no event carries a secret, a token or the connection.
  """
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias ApiGatehouse.Plug.RateLimit
  alias ApiGatehouse.Test.Flow
  alias ApiGatehouse.Test.Server
  alias ApiGatehouse.Test.TelemetryCapture
  alias ApiGatehouse.Test.User

  @origin [{"x-forwarded-for", "203.0.113.9"}, {"user-agent", "erp-sync/1.0"}]

  setup do
    TelemetryCapture.attach()
    user = User.admin()
    Map.put(Flow.create_client(user), :user, user)
  end

  defp token(client_id, secret, params \\ %{"grant_type" => "client_credentials"}) do
    Flow.post_form("/api/oauth/token", params, [
      {"authorization", Flow.basic(client_id, secret)} | @origin
    ])
  end

  defp revoke(client_id, secret, params) do
    Flow.post_form("/api/oauth/revoke", params, [
      {"authorization", Flow.basic(client_id, secret)} | @origin
    ])
  end

  test "Telemetry.events/0 lists every event, for attach_many/4" do
    assert Enum.sort(ApiGatehouse.Telemetry.events()) == [
             [:api_gatehouse, :rate_limit, :denied],
             [:api_gatehouse, :revocation, :accepted],
             [:api_gatehouse, :revocation, :refused],
             [:api_gatehouse, :token, :issued],
             [:api_gatehouse, :token, :refused],
             [:api_gatehouse, :token, :replayed]
           ]
  end

  test "an issued token names the grant, the client, its owner and company, the scopes and the origin",
       ctx do
    assert token(ctx.client_id, ctx.secret).status == 200

    assert_received {:telemetry, [:api_gatehouse, :token, :issued], %{system_time: _}, metadata}

    assert metadata == %{
             grant_type: :client_credentials,
             client_id: ctx.client_id,
             owner_id: ctx.user.id,
             company_id: ctx.user.company_id,
             scopes: ["read"],
             client_ip: "203.0.113.9",
             user_agent: "erp-sync/1.0"
           }
  end

  test "a refresh is an issued token of the refresh_token grant", ctx do
    %{"refresh_token" => refresh_token} = ctx.client_id |> token(ctx.secret) |> Flow.json()

    params = %{"grant_type" => "refresh_token", "refresh_token" => refresh_token}
    assert token(ctx.client_id, ctx.secret, params).status == 200

    assert_received {:telemetry, [:api_gatehouse, :token, :issued], _measurements, %{grant_type: :refresh_token}}
  end

  test "a failed client authentication is refused without naming a client", ctx do
    assert token(ctx.client_id, "wrong").status == 401

    assert_received {:telemetry, [:api_gatehouse, :token, :refused], %{system_time: _}, metadata}

    assert metadata == %{
             grant_type: :client_credentials,
             error: :invalid_client,
             description: "client authentication failed",
             client_id: nil,
             client_ip: "203.0.113.9",
             user_agent: "erp-sync/1.0"
           }
  end

  test "a refusal after the client authenticated names the client" do
    created = Flow.create_client(User.with_id(User.unloadable_id()))

    assert token(created.client_id, created.secret).status == 401

    assert_received {:telemetry, [:api_gatehouse, :token, :refused], _measurements, metadata}
    assert %{error: :invalid_client, client_id: client_id} = metadata
    assert client_id == created.client_id
  end

  test "a grant type the server does not know is not echoed back into the event", ctx do
    assert token(ctx.client_id, ctx.secret, %{"grant_type" => "password"}).status == 400

    assert_received {:telemetry, [:api_gatehouse, :token, :refused], _measurements,
                     %{grant_type: nil, error: :unsupported_grant_type}}
  end

  test "a replayed refresh token reports the family it revoked", ctx do
    %{"refresh_token" => replayed} = ctx.client_id |> token(ctx.secret) |> Flow.json()
    params = %{"grant_type" => "refresh_token", "refresh_token" => replayed}
    assert token(ctx.client_id, ctx.secret, params).status == 200
    replayed |> Flow.row_for_refresh() |> Flow.backdate(:revoked_at, 6)

    capture_log(fn -> assert token(ctx.client_id, ctx.secret, params).status == 400 end)

    assert_received {:telemetry, [:api_gatehouse, :token, :replayed], %{system_time: _, revoked: 1}, metadata}

    assert metadata == %{
             client_id: ctx.client_id,
             owner_id: ctx.user.id,
             company_id: ctx.user.company_id,
             client_ip: "203.0.113.9",
             user_agent: "erp-sync/1.0"
           }

    assert_received {:telemetry, [:api_gatehouse, :token, :refused], _measurements, %{error: :invalid_grant}}
  end

  test "a revocation reports whether it revoked a live token of the client, which its 200 never tells",
       ctx do
    %{"access_token" => access_token} = ctx.client_id |> token(ctx.secret) |> Flow.json()

    assert revoke(ctx.client_id, ctx.secret, %{"token" => access_token}).status == 200
    assert revoke(ctx.client_id, ctx.secret, %{"token" => access_token}).status == 200

    assert_received {:telemetry, [:api_gatehouse, :revocation, :accepted], %{system_time: _}, first}

    assert_received {:telemetry, [:api_gatehouse, :revocation, :accepted], _measurements, second}

    assert first == %{
             client_id: ctx.client_id,
             revoked: true,
             client_ip: "203.0.113.9",
             user_agent: "erp-sync/1.0"
           }

    assert %{revoked: false} = second
  end

  test "a revocation by a client that fails to authenticate is refused", ctx do
    assert revoke(ctx.client_id, "wrong", %{"token" => "anything"}).status == 401

    assert_received {:telemetry, [:api_gatehouse, :revocation, :refused], %{system_time: _},
                     %{error: :invalid_client, client_id: nil, client_ip: "203.0.113.9"}}
  end

  test "a rate-limited request reports its bucket, key and origin" do
    opts = RateLimit.init(bucket: "denied", limit: 1, server: Server)

    :post
    |> Plug.Test.conn("/")
    |> Plug.Conn.put_req_header("x-forwarded-for", "2001:db8:1:2::7")
    |> RateLimit.call(opts)

    assert_received {:telemetry, [:api_gatehouse, :rate_limit, :denied], %{system_time: _, retry_after_ms: 1_500},
                     metadata}

    assert metadata == %{
             bucket: "denied",
             key: "2001:db8:1:2::/64",
             limit: 1,
             period: 60_000,
             client_ip: "2001:db8:1:2::7",
             user_agent: nil
           }
  end

  test "a long user agent is cut short, so a caller cannot bloat the logs", ctx do
    headers = [
      {"authorization", Flow.basic(ctx.client_id, "wrong")},
      {"user-agent", String.duplicate("x", 5_000)}
    ]

    Flow.post_form("/api/oauth/token", %{"grant_type" => "client_credentials"}, headers)

    assert_received {:telemetry, [:api_gatehouse, :token, :refused], _measurements, %{user_agent: user_agent}}

    assert byte_size(user_agent) == 200
  end

  test "no event carries a secret or a token", ctx do
    tokens = ctx.client_id |> token(ctx.secret) |> Flow.json()
    refresh = %{"grant_type" => "refresh_token", "refresh_token" => tokens["refresh_token"]}
    rotated = ctx.client_id |> token(ctx.secret, refresh) |> Flow.json()
    token(ctx.client_id, ctx.secret <> "x")
    revoke(ctx.client_id, ctx.secret, %{"token" => rotated["access_token"]})

    events = collect()
    assert length(events) == 4

    for secret <- [
          ctx.secret,
          ctx.secret <> "x",
          tokens["access_token"],
          tokens["refresh_token"],
          rotated["access_token"],
          rotated["refresh_token"]
        ] do
      refute inspect(events, limit: :infinity, printable_limit: :infinity) =~ secret
    end
  end

  defp collect do
    receive do
      {:telemetry, _event, _measurements, _metadata} = event -> [event | collect()]
    after
      0 -> []
    end
  end
end
