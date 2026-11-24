defmodule ApiGatehouse.Plug.TokenTest do
  @moduledoc """
  The token endpoint. A client authenticates by HTTP Basic or by the body, never
  both, and only while it exists and its owner still loads; a token carries
  some of what the client may have; a refresh needs the client's credentials,
  rotates once, expires when idle, and a replayed one revokes the family. Every
  refusal is an OAuth error, never a crash.

  Single use under real concurrency is a property of the host's Postgres
  filtered UPDATE; the per-process ETS tables here prove the sequential replay
  and, through `RacingServer`, the lost race.
  """
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog
  import Plug.Conn

  alias ApiGatehouse.OAuth.ServerActor
  alias ApiGatehouse.Plug.Token
  alias ApiGatehouse.Test.AccessToken
  alias ApiGatehouse.Test.Client
  alias ApiGatehouse.Test.ConfiguredServer
  alias ApiGatehouse.Test.FailingServer
  alias ApiGatehouse.Test.Flow
  alias ApiGatehouse.Test.NoRefreshServer
  alias ApiGatehouse.Test.RacingServer
  alias ApiGatehouse.Test.User

  @basic_challenge [~s(Basic realm="oauth")]

  defp assert_error(conn, status, error) do
    assert conn.status == status
    assert %{"error" => ^error, "error_description" => description} = Flow.json(conn)
    assert is_binary(description)
    conn
  end

  defp assert_invalid_client(conn, challenge) do
    assert_error(conn, 401, "invalid_client")
    assert get_resp_header(conn, "www-authenticate") == challenge
  end

  defp assert_invalid_grant(conn), do: assert_error(conn, 400, "invalid_grant")

  defp issued(conn) do
    assert conn.status == 200
    Flow.json(conn)
  end

  defp delete(%{client: client}, user) do
    {:ok, _deleted} = Client.soft_delete(client, actor: user, tenant: user.company_id)
  end

  describe "client_credentials" do
    setup do
      user = User.admin()

      Map.put(Flow.create_client(user, %{scopes: ["read", "write"]}), :user, user)
    end

    test "issues a bearer token, with a refresh token, to HTTP Basic credentials", ctx do
      body = issued(Flow.token_basic(ctx.client_id, ctx.secret))

      assert %{
               "access_token" => access_token,
               "refresh_token" => refresh_token,
               "token_type" => "Bearer",
               "expires_in" => 3600,
               "scope" => "read write"
             } = body

      assert access_token =~ ~r/\A[A-Za-z0-9_-]{43}\z/
      assert refresh_token =~ ~r/\A[A-Za-z0-9_-]{43}\z/
      refute access_token == refresh_token
      assert Flow.authenticates?(access_token)
    end

    test "issues a token to credentials in the body", ctx do
      assert %{"access_token" => access_token} =
               issued(Flow.token_post(ctx.client_id, ctx.secret))

      assert Flow.authenticates?(access_token)
    end

    test "accepts a JSON body", ctx do
      conn =
        Flow.post_json("/api/oauth/token", %{
          "grant_type" => "client_credentials",
          "client_id" => ctx.client_id,
          "client_secret" => ctx.secret
        })

      assert conn.status == 200
    end

    test "matches the Basic scheme case-insensitively", ctx do
      "Basic " <> encoded = Flow.basic(ctx.client_id, ctx.secret)

      conn =
        Flow.post_form("/api/oauth/token", %{"grant_type" => "client_credentials"}, [
          {"authorization", "basic " <> encoded}
        ])

      assert conn.status == 200
    end

    test "accepts the same client_id in the body beside HTTP Basic", ctx do
      conn =
        Flow.token_basic(ctx.client_id, ctx.secret, %{
          "grant_type" => "client_credentials",
          "client_id" => ctx.client_id
        })

      assert conn.status == 200
    end

    test "refuses HTTP Basic and a body secret together", ctx do
      conn =
        Flow.token_basic(ctx.client_id, ctx.secret, %{
          "grant_type" => "client_credentials",
          "client_id" => ctx.client_id,
          "client_secret" => ctx.secret
        })

      assert_error(conn, 400, "invalid_request")
      assert Flow.rows() == []
    end

    test "refuses a body client_id that differs from the Basic one", ctx do
      %{client_id: other} = Flow.create_client(ctx.user)

      conn =
        Flow.token_basic(ctx.client_id, ctx.secret, %{
          "grant_type" => "client_credentials",
          "client_id" => other
        })

      assert_error(conn, 400, "invalid_request")
    end

    test "a wrong secret is invalid_client, challenged only when Basic was used", ctx do
      assert_invalid_client(Flow.token_basic(ctx.client_id, "not-the-secret"), @basic_challenge)
      assert_invalid_client(Flow.token_post(ctx.client_id, "not-the-secret"), [])
      assert Flow.rows() == []
    end

    test "an unknown client is the same invalid_client as a wrong secret", ctx do
      unknown = Flow.token_basic("never-issued", ctx.secret)
      wrong = Flow.token_basic(ctx.client_id, "not-the-secret")

      assert_invalid_client(unknown, @basic_challenge)
      assert unknown.resp_body == wrong.resp_body
    end

    test "missing credentials are invalid_client", ctx do
      assert_invalid_client(
        Flow.post_form("/api/oauth/token", %{"grant_type" => "client_credentials"}),
        []
      )

      assert_invalid_client(
        Flow.post_form("/api/oauth/token", %{
          "grant_type" => "client_credentials",
          "client_id" => ctx.client_id
        }),
        []
      )
    end

    test "malformed Basic credentials are challenged" do
      for header <- [
            "Basic not-base64!",
            "Basic " <> Base.encode64("no-colon"),
            "Basic " <> Base.encode64(":secret")
          ] do
        conn =
          Flow.post_form("/api/oauth/token", %{"grant_type" => "client_credentials"}, [
            {"authorization", header}
          ])

        assert_invalid_client(conn, @basic_challenge)
      end
    end

    test "credentials in the query string are ignored", ctx do
      query = URI.encode_query(%{"client_id" => ctx.client_id, "client_secret" => ctx.secret})

      conn = Flow.post_form("/api/oauth/token?" <> query, %{"grant_type" => "client_credentials"})

      assert_invalid_client(conn, [])
    end

    test "a deleted client gets no token", ctx do
      delete(ctx, ctx.user)

      assert_invalid_client(Flow.token_basic(ctx.client_id, ctx.secret), @basic_challenge)
      assert_invalid_client(Flow.token_post(ctx.client_id, ctx.secret), [])
    end

    test "a client whose owner no longer loads gets no token" do
      for owner_id <- [User.unloadable_id(), User.loads_as_nil_id(), User.in_other_company_id()] do
        owner = User.with_id(owner_id)
        %{client_id: client_id, secret: secret} = Flow.create_client(owner)

        assert_invalid_client(Flow.token_basic(client_id, secret), @basic_challenge)
        assert_invalid_client(Flow.token_post(client_id, secret), [])
      end

      assert Flow.rows() == []
    end

    test "an owner the host returns without a company is the host's to vouch for" do
      %{client_id: client_id, secret: secret} =
        Flow.create_client(User.with_id(User.without_company_id()))

      assert Flow.token_basic(client_id, secret).status == 200
    end

    test "scope narrows the token to some of the client's scopes", ctx do
      for {requested, granted} <- [
            {"read", "read"},
            {"write", "write"},
            {"write read", "write read"},
            {"", "read write"}
          ] do
        params = %{"grant_type" => "client_credentials", "scope" => requested}

        assert %{"scope" => ^granted} =
                 issued(Flow.token_basic(ctx.client_id, ctx.secret, params))
      end

      assert %{"scope" => "read"} =
               issued(
                 Flow.token_basic(ctx.client_id, ctx.secret, %{
                   "grant_type" => "client_credentials",
                   "scope" => "read  read"
                 })
               )
    end

    test "a scope beyond the client's is invalid_scope", ctx do
      %{client_id: read_only, secret: secret} = Flow.create_client(ctx.user, %{scopes: ["read"]})

      assert_error(
        Flow.token_basic(read_only, secret, %{
          "grant_type" => "client_credentials",
          "scope" => "write"
        }),
        400,
        "invalid_scope"
      )

      assert_error(
        Flow.token_basic(ctx.client_id, ctx.secret, %{
          "grant_type" => "client_credentials",
          "scope" => "read admin"
        }),
        400,
        "invalid_scope"
      )

      assert Flow.rows() == []
    end

    test "a scope that is not a string is invalid_request", ctx do
      conn =
        Flow.post_json("/api/oauth/token", %{
          "grant_type" => "client_credentials",
          "client_id" => ctx.client_id,
          "client_secret" => ctx.secret,
          "scope" => ["read"]
        })

      assert_error(conn, 400, "invalid_request")
    end

    test "the server's scopes, token lifetime and idle TTL apply", ctx do
      conn =
        Flow.token_through(ConfiguredServer, %{"grant_type" => "client_credentials"}, [
          {"authorization", Flow.basic(ctx.client_id, ctx.secret)}
        ])

      assert %{"scope" => "read", "expires_in" => 600, "access_token" => access_token} =
               issued(conn)

      row = Flow.row_for_access(access_token)
      assert_in_delta DateTime.diff(row.expires_at, DateTime.utc_now()), 600, 5
      assert_in_delta DateTime.diff(row.refresh_expires_at, DateTime.utc_now()), 60, 5

      refused =
        Flow.token_through(
          ConfiguredServer,
          %{"grant_type" => "client_credentials", "scope" => "write"},
          [
            {"authorization", Flow.basic(ctx.client_id, ctx.secret)}
          ]
        )

      assert_error(refused, 400, "invalid_scope")
    end

    test "a server that issues no refresh tokens issues none", ctx do
      conn =
        Flow.token_through(NoRefreshServer, %{"grant_type" => "client_credentials"}, [
          {"authorization", Flow.basic(ctx.client_id, ctx.secret)}
        ])

      body = issued(conn)
      refute Map.has_key?(body, "refresh_token")
      assert Flow.row_for_access(body["access_token"]).refresh_token_hash == nil
    end

    test "a token row that cannot be written is a logged server_error", ctx do
      log =
        capture_log(fn ->
          conn =
            Flow.token_through(FailingServer, %{"grant_type" => "client_credentials"}, [
              {"authorization", Flow.basic(ctx.client_id, ctx.secret)}
            ])

          assert conn.status == 500
          assert Flow.json(conn) == %{"error" => "server_error"}
        end)

      assert log =~ "could not issue a token to client #{ctx.client_id}"
      assert log =~ "write refused"
      refute log =~ ctx.secret
    end
  end

  describe "refresh_token" do
    setup do
      user = User.admin()

      Map.put(Flow.connect(user, %{scopes: ["read", "write"]}), :user, user)
    end

    test "rotates once: new tokens, and the old pair stops working", ctx do
      rotated = issued(Flow.refresh(ctx.client_id, ctx.secret, ctx.tokens["refresh_token"]))

      assert %{"token_type" => "Bearer", "expires_in" => 3600, "scope" => "read write"} = rotated
      refute rotated["refresh_token"] == ctx.tokens["refresh_token"]
      refute rotated["access_token"] == ctx.tokens["access_token"]

      assert Flow.authenticates?(rotated["access_token"])
      refute Flow.authenticates?(ctx.tokens["access_token"])
      assert_invalid_grant(Flow.refresh(ctx.client_id, ctx.secret, ctx.tokens["refresh_token"]))

      spent = Flow.row_for_refresh(ctx.tokens["refresh_token"])
      assert spent.rotated_at
      assert spent.revoked_at == spent.rotated_at
    end

    test "each rotation issues a refresh token with a fresh idle expiry", ctx do
      ctx.tokens["refresh_token"]
      |> Flow.row_for_refresh()
      |> Flow.backdate(:refresh_expires_at, -60)

      rotated = issued(Flow.refresh(ctx.client_id, ctx.secret, ctx.tokens["refresh_token"]))
      row = Flow.row_for_refresh(rotated["refresh_token"])

      assert_in_delta DateTime.diff(row.refresh_expires_at, DateTime.utc_now()), 90 * 24 * 3600, 5
    end

    test "works with credentials in the body", ctx do
      conn =
        Flow.token_post(ctx.client_id, ctx.secret, %{
          "grant_type" => "refresh_token",
          "refresh_token" => ctx.tokens["refresh_token"]
        })

      assert conn.status == 200
    end

    test "requires client authentication", ctx do
      unauthenticated =
        Flow.post_form("/api/oauth/token", %{
          "grant_type" => "refresh_token",
          "refresh_token" => ctx.tokens["refresh_token"]
        })

      assert_invalid_client(unauthenticated, [])

      with_client_id_only =
        Flow.post_form("/api/oauth/token", %{
          "grant_type" => "refresh_token",
          "refresh_token" => ctx.tokens["refresh_token"],
          "client_id" => ctx.client_id
        })

      assert_invalid_client(with_client_id_only, [])

      assert_invalid_client(
        Flow.refresh(ctx.client_id, "not-the-secret", ctx.tokens["refresh_token"]),
        @basic_challenge
      )

      assert is_nil(Flow.row_for_refresh(ctx.tokens["refresh_token"]).revoked_at)
      assert Flow.authenticates?(ctx.tokens["access_token"])
    end

    test "another client's credentials cannot rotate the refresh token", ctx do
      other = Flow.create_client(ctx.user)

      assert_invalid_grant(Flow.refresh(other.client_id, other.secret, ctx.tokens["refresh_token"]))

      assert is_nil(Flow.row_for_refresh(ctx.tokens["refresh_token"]).revoked_at)
      assert Flow.refresh(ctx.client_id, ctx.secret, ctx.tokens["refresh_token"]).status == 200
    end

    test "a replay within the five-second grace period is refused but leaves the successor alone",
         ctx do
      rotated = issued(Flow.refresh(ctx.client_id, ctx.secret, ctx.tokens["refresh_token"]))
      ctx.tokens["refresh_token"] |> Flow.row_for_refresh() |> Flow.backdate(:revoked_at, 4)

      log =
        capture_log(fn ->
          assert_invalid_grant(Flow.refresh(ctx.client_id, ctx.secret, ctx.tokens["refresh_token"]))
        end)

      assert log == ""
      assert Flow.authenticates?(rotated["access_token"])
      assert Flow.refresh(ctx.client_id, ctx.secret, rotated["refresh_token"]).status == 200
    end

    test "a replay after the grace period revokes the whole family", ctx do
      rotated = issued(Flow.refresh(ctx.client_id, ctx.secret, ctx.tokens["refresh_token"]))
      sibling = issued(Flow.token_basic(ctx.client_id, ctx.secret))
      bystander = Flow.connect(ctx.user)
      ctx.tokens["refresh_token"] |> Flow.row_for_refresh() |> Flow.backdate(:revoked_at, 6)

      log =
        capture_log(fn ->
          assert_invalid_grant(Flow.refresh(ctx.client_id, ctx.secret, ctx.tokens["refresh_token"]))
        end)

      assert log =~ "[warning]"
      assert log =~ "revoked 2 live token(s) of client #{ctx.client_id}"
      assert log =~ ctx.user.id

      for token <- [ctx.tokens, rotated, sibling, bystander.tokens],
          value <- [token["access_token"], token["refresh_token"]] do
        refute log =~ value
      end

      for successor <- [rotated, sibling] do
        refute Flow.authenticates?(successor["access_token"])
        assert Flow.row_for_refresh(successor["refresh_token"]).revoked_at
        assert is_nil(Flow.row_for_refresh(successor["refresh_token"]).rotated_at)
      end

      assert Flow.authenticates?(bystander.tokens["access_token"])
    end

    test "a refresh token revoked through the revocation endpoint and presented later revokes the family",
         ctx do
      sibling = issued(Flow.token_basic(ctx.client_id, ctx.secret))

      assert Flow.revoke(ctx.client_id, ctx.secret, %{"token" => ctx.tokens["refresh_token"]}).status ==
               200

      ctx.tokens["refresh_token"] |> Flow.row_for_refresh() |> Flow.backdate(:revoked_at, 6)

      capture_log(fn ->
        assert_invalid_grant(Flow.refresh(ctx.client_id, ctx.secret, ctx.tokens["refresh_token"]))
      end)

      refute Flow.authenticates?(sibling["access_token"])
    end

    test "a family that cannot be revoked is a logged server_error", ctx do
      assert Flow.refresh(ctx.client_id, ctx.secret, ctx.tokens["refresh_token"]).status == 200
      ctx.tokens["refresh_token"] |> Flow.row_for_refresh() |> Flow.backdate(:revoked_at, 10)

      log =
        capture_log(fn ->
          conn =
            Flow.token_through(
              FailingServer,
              %{"grant_type" => "refresh_token", "refresh_token" => ctx.tokens["refresh_token"]},
              [{"authorization", Flow.basic(ctx.client_id, ctx.secret)}]
            )

          assert conn.status == 500
          assert Flow.json(conn) == %{"error" => "server_error"}
        end)

      assert log =~ "[error]"
      assert log =~ "could not be revoked"
      assert log =~ "write refused"
      refute log =~ ctx.tokens["refresh_token"]
    end

    test "losing a rotation race is invalid_grant and issues nothing", ctx do
      conn =
        Flow.token_through(
          RacingServer,
          %{"grant_type" => "refresh_token", "refresh_token" => ctx.tokens["refresh_token"]},
          [{"authorization", Flow.basic(ctx.client_id, ctx.secret)}]
        )

      assert_invalid_grant(conn)
      assert length(Flow.rows()) == 1
    end

    test "a refresh token idle past its expiry no longer rotates", ctx do
      ctx.tokens["refresh_token"]
      |> Flow.row_for_refresh()
      |> Flow.backdate(:refresh_expires_at, 1)

      assert_invalid_grant(Flow.refresh(ctx.client_id, ctx.secret, ctx.tokens["refresh_token"]))
      assert is_nil(Flow.row_for_refresh(ctx.tokens["refresh_token"]).revoked_at)
    end

    test "a refresh token still within its idle expiry rotates although its access token expired",
         ctx do
      ctx.tokens["refresh_token"] |> Flow.row_for_refresh() |> Flow.backdate(:expires_at, 60)

      refute Flow.authenticates?(ctx.tokens["access_token"])
      assert Flow.refresh(ctx.client_id, ctx.secret, ctx.tokens["refresh_token"]).status == 200
    end

    test "scope narrows a refresh to some of the refreshed token's scopes", ctx do
      narrowed =
        issued(
          Flow.refresh(ctx.client_id, ctx.secret, ctx.tokens["refresh_token"], %{
            "scope" => "read"
          })
        )

      assert narrowed["scope"] == "read"

      assert_error(
        Flow.refresh(ctx.client_id, ctx.secret, narrowed["refresh_token"], %{"scope" => "write"}),
        400,
        "invalid_scope"
      )

      assert is_nil(Flow.row_for_refresh(narrowed["refresh_token"]).revoked_at)

      assert %{"scope" => "read"} =
               issued(Flow.refresh(ctx.client_id, ctx.secret, narrowed["refresh_token"]))
    end

    test "an access token is not a refresh token", ctx do
      assert_invalid_grant(Flow.refresh(ctx.client_id, ctx.secret, ctx.tokens["access_token"]))
      assert Flow.authenticates?(ctx.tokens["access_token"])
    end

    test "an unknown refresh token is invalid_grant, a missing one invalid_request", ctx do
      assert_invalid_grant(Flow.refresh(ctx.client_id, ctx.secret, "never-issued"))

      assert_error(
        Flow.token_basic(ctx.client_id, ctx.secret, %{"grant_type" => "refresh_token"}),
        400,
        "invalid_request"
      )
    end

    test "a deleted client cannot refresh", ctx do
      delete(ctx, ctx.user)

      assert_invalid_client(
        Flow.refresh(ctx.client_id, ctx.secret, ctx.tokens["refresh_token"]),
        @basic_challenge
      )
    end

    test "a client whose owner no longer loads cannot refresh" do
      owner = User.with_id(User.unloadable_id())
      created = Flow.create_client(owner)
      row = Flow.issue(created.client)

      assert_invalid_client(
        Flow.refresh(created.client_id, created.secret, row.__metadata__.refresh_token),
        @basic_challenge
      )

      assert is_nil(Flow.row_for_refresh(row.__metadata__.refresh_token).revoked_at)
    end

    test "a server that issues no refresh tokens refuses the grant as unauthorized_client", ctx do
      conn =
        Flow.token_through(
          NoRefreshServer,
          %{"grant_type" => "refresh_token", "refresh_token" => ctx.tokens["refresh_token"]},
          [{"authorization", Flow.basic(ctx.client_id, ctx.secret)}]
        )

      assert_error(conn, 400, "unauthorized_client")
      assert is_nil(Flow.row_for_refresh(ctx.tokens["refresh_token"]).revoked_at)
    end
  end

  test "an unsupported or missing grant type is refused" do
    %{client_id: client_id, secret: secret} = Flow.create_client(User.admin())

    for grant_type <- [
          "password",
          "authorization_code",
          "urn:ietf:params:oauth:grant-type:jwt-bearer"
        ] do
      conn = Flow.token_basic(client_id, secret, %{"grant_type" => grant_type})

      assert_error(conn, 400, "unsupported_grant_type")
    end

    assert_error(Flow.token_basic(client_id, secret, %{}), 400, "invalid_request")
  end

  test "token responses forbid storage, whether issued or refused" do
    %{client_id: client_id, secret: secret} = Flow.create_client(User.admin())

    for conn <- [Flow.token_basic(client_id, secret), Flow.token_basic(client_id, "wrong")] do
      assert get_resp_header(conn, "cache-control") == ["no-store"]
      assert get_resp_header(conn, "pragma") == ["no-cache"]
      assert ["application/json" <> _charset] = get_resp_header(conn, "content-type")
    end
  end

  test "an endpoint without a server raises before issuing anything" do
    %{client_id: client_id, secret: secret} = Flow.create_client(User.admin())

    assert_raise ArgumentError, ~r/ApiGatehouse.Plug.Token has no API server/, fn ->
      :post
      |> Plug.Test.conn("/api/oauth/token", %{"grant_type" => "client_credentials"})
      |> put_req_header("authorization", Flow.basic(client_id, secret))
      |> Token.call(Token.init([]))
    end

    assert {:ok, []} = AccessToken.read(actor: ServerActor.new())
  end
end
