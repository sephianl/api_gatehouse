defmodule ApiGatehouse.Plug.BearerTest do
  @moduledoc """
  The API resolves its actor and tenant from an access token and nothing else,
  re-checking the token, its client and its owner on every request. Every way a
  credential can be missing, wrong or stale is a 401 with an RFC 6750
  challenge, and a host loader that returns the wrong user cannot authenticate
  across companies.
  """
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias ApiGatehouse.OAuth.ServerActor
  alias ApiGatehouse.Plug.Bearer
  alias ApiGatehouse.Test.AccessToken
  alias ApiGatehouse.Test.Client
  alias ApiGatehouse.Test.Flow
  alias ApiGatehouse.Test.Server
  alias ApiGatehouse.Test.User
  alias Ash.PlugHelpers

  defp with_header(value) do
    :get |> conn("/api/json/whoami") |> put_req_header("authorization", value) |> Flow.request()
  end

  defp assert_challenged(conn, challenge) do
    assert conn.status == 401
    assert conn.halted
    assert Flow.json(conn) == %{"error" => "invalid_token"}
    assert get_resp_header(conn, "www-authenticate") == [challenge]
  end

  defp assert_invalid(conn), do: assert_challenged(conn, ~s(Bearer error="invalid_token"))

  defp token_for(user, opts \\ []) do
    %{client: client} = Flow.create_client(user)

    Flow.issue(client, opts).__metadata__.access_token
  end

  test "a request without a credential is challenged without an error code" do
    assert_challenged(Flow.api(:get, "/whoami", nil), "Bearer")
  end

  test "a non-bearer credential is challenged without an error code" do
    assert_challenged(with_header("Basic dXNlcjpwYXNz"), "Bearer")
    assert_challenged(with_header("Bearer "), "Bearer")
    assert_challenged(with_header("Bearer"), "Bearer")
  end

  test "an unknown token is rejected" do
    assert_invalid(Flow.api(:get, "/whoami", "not-a-real-token"))
  end

  test "a refresh token is not an access token" do
    %{client: client} = Flow.create_client(User.admin())

    assert_invalid(Flow.api(:get, "/whoami", Flow.issue(client).__metadata__.refresh_token))
  end

  test "an expired token is rejected" do
    %{client: client} = Flow.create_client(User.admin())
    row = Flow.issue(client)
    Flow.backdate(row, :expires_at, 1)

    assert_invalid(Flow.api(:get, "/whoami", row.__metadata__.access_token))
  end

  test "a revoked token is rejected" do
    %{client: client} = Flow.create_client(User.admin())
    row = Flow.issue(client)
    {:ok, _revoked} = AccessToken.revoke(row, actor: ServerActor.new())

    assert_invalid(Flow.api(:get, "/whoami", row.__metadata__.access_token))
  end

  test "a token of a deleted client is rejected, even if it was not revoked" do
    user = User.admin()
    %{client: client} = Flow.create_client(user)
    row = Flow.issue(client)
    assert Flow.authenticates?(row.__metadata__.access_token)

    {:ok, _deleted} = Client.soft_delete(client, actor: user, tenant: user.company_id)
    later = Flow.issue(client)

    assert_invalid(Flow.api(:get, "/whoami", row.__metadata__.access_token))
    assert is_nil(Flow.row_for_access(later.__metadata__.access_token).revoked_at)
    assert_invalid(Flow.api(:get, "/whoami", later.__metadata__.access_token))
  end

  test "a token whose owner or company is not its client's is rejected" do
    %{client: client} = Flow.create_client(User.admin())

    assert_invalid(
      Flow.api(
        :get,
        "/whoami",
        Flow.issue(client, owner_id: Ash.UUID.generate()).__metadata__.access_token
      )
    )

    assert_invalid(
      Flow.api(
        :get,
        "/whoami",
        Flow.issue(client, company_id: Ash.UUID.generate()).__metadata__.access_token
      )
    )
  end

  test "a token whose owner no longer loads is rejected" do
    for owner_id <- [User.unloadable_id(), User.loads_as_nil_id(), User.in_other_company_id()] do
      assert_invalid(Flow.api(:get, "/whoami", token_for(User.with_id(owner_id))))
    end
  end

  test "an owner without a company key is the host's to vouch for" do
    assert Flow.api(:get, "/whoami", token_for(User.with_id(User.without_company_id()))).status ==
             200
  end

  test "the scheme is matched case-insensitively" do
    token = token_for(User.admin())

    for scheme <- ["Bearer", "bearer", "BEARER", "bEaReR"] do
      assert with_header("#{scheme} #{token}").status == 200, "#{scheme} was refused"
    end
  end

  test "revocation and deletion take effect on the very next request" do
    user = User.admin()
    %{client: client, tokens: tokens} = Flow.connect(user)
    other = Flow.issue(client)

    assert Flow.authenticates?(tokens["access_token"])

    {:ok, _revoked} =
      tokens["access_token"]
      |> Flow.row_for_access()
      |> AccessToken.revoke(actor: ServerActor.new())

    refute Flow.authenticates?(tokens["access_token"])

    assert Flow.authenticates?(other.__metadata__.access_token)
    {:ok, _deleted} = Client.soft_delete(client, actor: user, tenant: user.company_id)
    refute Flow.authenticates?(other.__metadata__.access_token)
  end

  describe "an authenticated request" do
    setup do
      user = User.admin()
      %{client: client} = Flow.create_client(user, %{scopes: ["read", "write"]})
      row = Flow.issue(client, scopes: ["read"])

      conn =
        :get
        |> conn("/")
        |> put_req_header("authorization", "Bearer " <> row.__metadata__.access_token)
        |> PlugHelpers.set_context(%{
          upstream: :kept,
          api_gatehouse: %{scopes: ["read", "write"], forged: true},
          shared: %{locale: "nl"}
        })
        |> Bearer.call(Bearer.init(server: Server))

      %{conn: conn, user: user, client: client, row: row}
    end

    test "carries the client's owner as actor and its company as tenant", %{
      conn: conn,
      user: user
    } do
      refute conn.halted
      assert %User{id: id, company_id: company_id} = PlugHelpers.get_actor(conn)
      assert id == user.id
      assert company_id == user.company_id
      assert PlugHelpers.get_tenant(conn) == user.company_id
    end

    test "replaces any upstream api_gatehouse context, also under shared, and keeps the rest",
         ctx do
      gatehouse = %{scopes: ["read"], client_id: ctx.client.client_id}

      assert PlugHelpers.get_context(ctx.conn) == %{
               upstream: :kept,
               api_gatehouse: gatehouse,
               shared: %{locale: "nl", api_gatehouse: gatehouse}
             }
    end

    test "assigns the token and client rows for host plugs", ctx do
      assert ctx.conn.assigns.api_gatehouse_token.id == ctx.row.id
      assert ctx.conn.assigns.api_gatehouse_client.id == ctx.client.id
    end
  end

  test "the API behind it sees the actor, tenant and context" do
    user = User.admin()
    %{client_id: client_id, tokens: tokens} = Flow.connect(user)

    assert %{
             "actor" => user.id,
             "tenant" => user.company_id,
             "api_gatehouse" => %{"scopes" => ["read"], "client_id" => client_id}
           } == "/whoami" |> then(&Flow.api(:get, &1, tokens["access_token"])) |> Flow.json()
  end

  describe "authenticate/2" do
    test "decides like the plug but sends nothing and halts nothing" do
      user = User.admin()
      %{tokens: tokens} = Flow.connect(user)

      request = fn header ->
        if header,
          do: put_req_header(conn(:get, "/"), "authorization", header),
          else: conn(:get, "/")
      end

      assert {:ok, conn} =
               Bearer.authenticate(request.("Bearer " <> tokens["access_token"]), Server)

      refute conn.halted
      assert is_nil(conn.status)
      assert PlugHelpers.get_actor(conn).id == user.id

      assert {:error, :missing} = Bearer.authenticate(request.(nil), Server)
      assert {:error, :missing} = Bearer.authenticate(request.("Basic abc"), Server)
      assert {:error, :invalid_token} = Bearer.authenticate(request.("Bearer nope"), Server)
    end
  end
end
