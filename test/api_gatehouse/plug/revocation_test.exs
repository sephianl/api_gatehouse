defmodule ApiGatehouse.Plug.RevocationTest do
  @moduledoc """
  RFC 7009 revocation: the client authenticates as at the token endpoint, may
  revoke an access or a refresh token it was issued, and is answered 200
  whatever the token turned out to be. Another client's tokens are left alone.
  """
  use ExUnit.Case, async: true

  import Plug.Conn

  alias ApiGatehouse.Test.Client
  alias ApiGatehouse.Test.Flow
  alias ApiGatehouse.Test.User

  setup do
    user = User.admin()

    Map.put(Flow.connect(user), :user, user)
  end

  defp assert_revoked_ok(conn) do
    assert conn.status == 200
    assert conn.resp_body == ""
  end

  test "the owning client revokes an access token, and its refresh token with it", ctx do
    assert_revoked_ok(Flow.revoke(ctx.client_id, ctx.secret, %{"token" => ctx.tokens["access_token"]}))

    refute Flow.authenticates?(ctx.tokens["access_token"])
    assert Flow.row_for_refresh(ctx.tokens["refresh_token"]).revoked_at
    assert Flow.refresh(ctx.client_id, ctx.secret, ctx.tokens["refresh_token"]).status == 400
  end

  test "the owning client revokes a refresh token, and its access token with it", ctx do
    assert_revoked_ok(Flow.revoke(ctx.client_id, ctx.secret, %{"token" => ctx.tokens["refresh_token"]}))

    refute Flow.authenticates?(ctx.tokens["access_token"])
    assert Flow.refresh(ctx.client_id, ctx.secret, ctx.tokens["refresh_token"]).status == 400
  end

  test "token_type_hint only decides the lookup order", ctx do
    second = ctx.client_id |> Flow.token_basic(ctx.secret) |> Flow.json()

    assert_revoked_ok(
      Flow.revoke(ctx.client_id, ctx.secret, %{
        "token" => ctx.tokens["refresh_token"],
        "token_type_hint" => "refresh_token"
      })
    )

    assert_revoked_ok(
      Flow.revoke(ctx.client_id, ctx.secret, %{
        "token" => second["access_token"],
        "token_type_hint" => "refresh_token"
      })
    )

    refute Flow.authenticates?(ctx.tokens["access_token"])
    refute Flow.authenticates?(second["access_token"])
  end

  test "credentials in the body work too", ctx do
    conn =
      Flow.post_form("/api/oauth/revoke", %{
        "client_id" => ctx.client_id,
        "client_secret" => ctx.secret,
        "token" => ctx.tokens["access_token"]
      })

    assert_revoked_ok(conn)
    refute Flow.authenticates?(ctx.tokens["access_token"])
  end

  test "another client's token is answered 200 and left alone", ctx do
    other = Flow.create_client(ctx.user)

    for token <- [ctx.tokens["access_token"], ctx.tokens["refresh_token"]] do
      assert_revoked_ok(Flow.revoke(other.client_id, other.secret, %{"token" => token}))
    end

    assert Flow.authenticates?(ctx.tokens["access_token"])
    assert is_nil(Flow.row_for_refresh(ctx.tokens["refresh_token"]).revoked_at)
  end

  test "an unknown token, or one revoked already, is answered 200", ctx do
    assert_revoked_ok(Flow.revoke(ctx.client_id, ctx.secret, %{"token" => "never-issued"}))

    params = %{"token" => ctx.tokens["access_token"]}
    assert_revoked_ok(Flow.revoke(ctx.client_id, ctx.secret, params))
    assert_revoked_ok(Flow.revoke(ctx.client_id, ctx.secret, params))

    assert_revoked_ok(Flow.revoke(ctx.client_id, ctx.secret, %{"token" => ctx.tokens["refresh_token"]}))
  end

  test "a missing token is invalid_request", ctx do
    for params <- [%{}, %{"token" => ""}] do
      conn = Flow.revoke(ctx.client_id, ctx.secret, params)

      assert conn.status == 400
      assert %{"error" => "invalid_request"} = Flow.json(conn)
    end
  end

  test "requires client authentication", ctx do
    unauthenticated =
      Flow.post_form("/api/oauth/revoke", %{"token" => ctx.tokens["access_token"]})

    assert unauthenticated.status == 401
    assert %{"error" => "invalid_client"} = Flow.json(unauthenticated)
    assert get_resp_header(unauthenticated, "www-authenticate") == []

    wrong = Flow.revoke(ctx.client_id, "not-the-secret", %{"token" => ctx.tokens["access_token"]})

    assert wrong.status == 401
    assert get_resp_header(wrong, "www-authenticate") == [~s(Basic realm="oauth")]
    assert Flow.authenticates?(ctx.tokens["access_token"])
  end

  test "HTTP Basic and a body secret together are invalid_request", ctx do
    conn =
      Flow.revoke(ctx.client_id, ctx.secret, %{
        "token" => ctx.tokens["access_token"],
        "client_secret" => ctx.secret
      })

    assert conn.status == 400
    assert %{"error" => "invalid_request"} = Flow.json(conn)
    assert Flow.authenticates?(ctx.tokens["access_token"])
  end

  test "a deleted client cannot authenticate to revoke", ctx do
    {:ok, _deleted} = Client.soft_delete(ctx.client, actor: ctx.user, tenant: ctx.user.company_id)

    assert Flow.revoke(ctx.client_id, ctx.secret, %{"token" => ctx.tokens["access_token"]}).status ==
             401
  end

  test "a client whose owner lost access can still revoke its tokens" do
    created = Flow.create_client(User.with_id(User.unloadable_id()))
    row = Flow.issue(created.client)

    assert_revoked_ok(Flow.revoke(created.client_id, created.secret, %{"token" => row.__metadata__.access_token}))

    assert Flow.row_for_refresh(row.__metadata__.refresh_token).revoked_at
  end

  test "the response forbids storage", ctx do
    conn = Flow.revoke(ctx.client_id, ctx.secret, %{"token" => "never-issued"})

    assert get_resp_header(conn, "cache-control") == ["no-store"]
  end
end
