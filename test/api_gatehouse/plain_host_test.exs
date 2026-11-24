defmodule ApiGatehouse.PlainHostTest do
  @moduledoc """
  A host whose client resource has no multitenancy and a broad policy of its
  own behind the server actor bypass: its users manage only their company's
  clients, and the whole flow — token, bearer, refresh, revoke, delete — works
  as it does for the multitenant host.
  """
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias ApiGatehouse.Plug.Bearer
  alias ApiGatehouse.Plug.Revocation
  alias ApiGatehouse.Test.Flow
  alias ApiGatehouse.Test.PlainClient
  alias ApiGatehouse.Test.PlainServer
  alias ApiGatehouse.Test.User
  alias Ash.PlugHelpers

  defp token(params, client_id, secret) do
    Flow.token_through(PlainServer, params, [{"authorization", Flow.basic(client_id, secret)}])
  end

  defp bearer(access_token) do
    :get
    |> conn("/")
    |> put_req_header("authorization", "Bearer " <> access_token)
    |> Bearer.call(Bearer.init(server: PlainServer))
  end

  test "the whole flow works for a client resource without multitenancy" do
    user = User.admin()

    {:ok, client} =
      PlainClient.create(
        %{name: "BI export", owner_id: user.id, company_id: user.company_id, scopes: ["read"]},
        actor: user
      )

    secret = client.__metadata__.client_secret

    issued =
      %{"grant_type" => "client_credentials"} |> token(client.client_id, secret) |> Flow.json()

    authenticated = bearer(issued["access_token"])
    refute authenticated.halted
    assert PlugHelpers.get_tenant(authenticated) == user.company_id

    rotated =
      %{"grant_type" => "refresh_token", "refresh_token" => issued["refresh_token"]}
      |> token(client.client_id, secret)
      |> Flow.json()

    assert bearer(issued["access_token"]).status == 401
    refute bearer(rotated["access_token"]).halted

    revoked =
      :post
      |> conn("/", %{"token" => rotated["access_token"]})
      |> put_req_header("authorization", Flow.basic(client.client_id, secret))
      |> Revocation.call(Revocation.init(server: PlainServer))

    assert revoked.status == 200
    assert bearer(rotated["access_token"]).status == 401

    last =
      %{"grant_type" => "client_credentials"} |> token(client.client_id, secret) |> Flow.json()

    {:ok, _deleted} = PlainClient.soft_delete(client, actor: user)

    assert bearer(last["access_token"]).status == 401
    assert token(%{"grant_type" => "client_credentials"}, client.client_id, secret).status == 401
  end

  test "the host's broad policy still keeps users to their own company" do
    user = User.admin()
    stranger = User.admin()

    {:ok, client} =
      PlainClient.create(%{name: "BI export", owner_id: user.id, company_id: user.company_id},
        actor: user
      )

    worker = User.worker()

    assert {:error, %Ash.Error.Forbidden{}} =
             PlainClient.create(%{name: "x", owner_id: worker.id, company_id: worker.company_id},
               actor: worker
             )

    assert {:ok, []} = PlainClient.list_for_company(user.company_id, actor: stranger)
    assert {:ok, [%{id: id}]} = PlainClient.list_for_company(user.company_id, actor: user)
    assert id == client.id
    assert {:error, _not_found} = PlainClient.get_by_client_id(client.client_id, actor: stranger)
  end
end
