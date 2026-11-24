defmodule ApiGatehouse.OAuth.ClientTest do
  @moduledoc """
  The client fragment's actions on a host resource with attribute multitenancy
  and host policies: a secret is returned once and stored as a bcrypt hash,
  scopes must be the server's, deleted clients drop out of every lookup and lose
  their tokens, and the server actor's lookups work beside the host's policies.
  """
  use ExUnit.Case, async: true

  alias ApiGatehouse.OAuth.ClientSecret
  alias ApiGatehouse.OAuth.ServerActor
  alias ApiGatehouse.Resource.Info
  alias ApiGatehouse.Test.Client
  alias ApiGatehouse.Test.Flow
  alias ApiGatehouse.Test.User
  alias Ash.Error.Changes.StaleRecord
  alias Ash.Error.Forbidden
  alias Ash.Error.Invalid

  setup do
    %{user: User.admin()}
  end

  defp as(user), do: [actor: user, tenant: user.company_id]

  test "create returns the secret once and stores only its bcrypt hash", %{user: user} do
    %{client: client, secret: secret} = Flow.create_client(user)

    assert client.client_id =~ ~r/\A[A-Za-z0-9_-]{22}\z/
    assert secret =~ ~r/\A[A-Za-z0-9_-]{43}\z/
    assert "$2b$" <> _rest = client.client_secret_hash
    assert ClientSecret.verify(secret, client.client_secret_hash)
    refute inspect(client) =~ secret
    refute inspect(client) =~ client.client_secret_hash

    {:ok, reread} = Client.get_by_client_id(client.client_id, actor: ServerActor.new())
    refute Map.has_key?(reread.__metadata__, :client_secret)
    refute reread.client_secret_hash == secret
    assert client.owner_id == user.id
    assert client.company_id == user.company_id
    assert client.scopes == ["read"]
  end

  test "every client gets its own id and secret", %{user: user} do
    created = for _client <- 1..5, do: Flow.create_client(user)

    assert created |> Enum.map(& &1.client_id) |> Enum.uniq() |> length() == 5
    assert created |> Enum.map(& &1.secret) |> Enum.uniq() |> length() == 5
  end

  test "a client id or secret hash cannot be passed in", %{user: user} do
    assert {:error, %Invalid{errors: errors}} =
             Client.create(
               %{
                 name: "x",
                 owner_id: user.id,
                 company_id: user.company_id,
                 client_id: "mine",
                 client_secret_hash: "mine"
               },
               as(user)
             )

    assert errors |> Enum.map(& &1.input) |> Enum.sort() == [:client_id, :client_secret_hash]
  end

  test "scopes must be a non-empty, duplicate-free subset of the server's", %{user: user} do
    for scopes <- [["admin"], ["read", "admin"], [], ["read", "read"]] do
      assert {:error, %Invalid{errors: errors}} =
               Client.create(
                 %{name: "x", owner_id: user.id, company_id: user.company_id, scopes: scopes},
                 as(user)
               )

      assert Enum.any?(errors, &match?(%{field: :scopes}, &1)), "#{inspect(scopes)} was accepted"
    end

    assert %{client: %{scopes: ["write", "read"]}} =
             Flow.create_client(user, %{scopes: ["write", "read"]})
  end

  test "a name is required", %{user: user} do
    assert {:error, %Invalid{}} =
             Client.create(%{owner_id: user.id, company_id: user.company_id}, as(user))
  end

  test "the client resource names its server" do
    assert Info.api_gatehouse_server!(Client) == ApiGatehouse.Test.Server
  end

  test "a client resource without a server is a compile-time warning, fatal under --warnings-as-errors" do
    warnings =
      ExUnit.CaptureIO.capture_io(:stderr, fn ->
        Code.compile_string("""
        defmodule ApiGatehouse.Test.ServerlessClient do
          use Ash.Resource,
            domain: nil,
            validate_domain_inclusion?: false,
            data_layer: Ash.DataLayer.Ets,
            fragments: [ApiGatehouse.OAuth.ClientFragment]

          def testing_identities, do: true
        end
        """)
      end)

    assert warnings =~ "a client resource must name its server"
  end

  describe "lookups" do
    test "by client id and by id find live clients, across tenants, for the server actor", %{
      user: user
    } do
      %{client: client} = Flow.create_client(user)

      assert {:ok, %{id: id}} =
               Client.get_by_client_id(client.client_id, actor: ServerActor.new())

      assert id == client.id
      assert {:ok, %{id: ^id}} = Client.get_by_id(client.id, actor: ServerActor.new())
    end

    test "deleted clients are not found", %{user: user} do
      %{client: client} = Flow.create_client(user)
      {:ok, deleted} = Client.soft_delete(client, as(user))

      assert deleted.deleted_at

      assert {:error, _not_found} =
               Client.get_by_client_id(client.client_id, actor: ServerActor.new())

      assert {:error, _not_found} = Client.get_by_id(client.id, actor: ServerActor.new())
    end

    test "nobody but the server actor looks clients up", %{user: user} do
      %{client: client} = Flow.create_client(user)

      for actor <- [user, nil] do
        assert {:error, _forbidden} = Client.get_by_client_id(client.client_id, actor: actor)
        assert {:error, _forbidden} = Client.get_by_id(client.id, actor: actor)
      end
    end
  end

  describe "list_for_company" do
    test "lists the company's live clients, newest first", %{user: user} do
      first = Flow.create_client(user, %{name: "first"})
      second = Flow.create_client(user, %{name: "second"})
      third = Flow.create_client(user, %{name: "third"})
      _elsewhere = Flow.create_client(User.admin(), %{name: "elsewhere"})
      {:ok, _deleted} = Client.soft_delete(second.client, as(user))

      {:ok, listed} = Client.list_for_company(user.company_id, as(user))

      assert Enum.map(listed, & &1.id) == [third.client.id, first.client.id]
    end

    test "another tenant sees nothing", %{user: user} do
      Flow.create_client(user)
      other = User.admin()

      assert {:ok, []} = Client.list_for_company(user.company_id, as(other))
    end
  end

  describe "soft_delete" do
    test "revokes every live token of the client and no other", %{user: user} do
      %{client: client, tokens: tokens} = Flow.connect(user)
      second = Flow.issue(client)
      bystander = Flow.connect(user)

      {:ok, _deleted} = Client.soft_delete(client, as(user))

      assert Flow.row_for_refresh(tokens["refresh_token"]).revoked_at
      assert Flow.row_for_refresh(second.__metadata__.refresh_token).revoked_at
      assert Flow.authenticates?(bystander.tokens["access_token"])
    end

    test "deletes once", %{user: user} do
      %{client: client} = Flow.create_client(user)

      assert {:ok, _deleted} = Client.soft_delete(client, as(user))
      assert {:error, %Invalid{errors: [%StaleRecord{}]}} = Client.soft_delete(client, as(user))
    end
  end

  describe "host policies" do
    test "a user the host's policies refuse cannot create, list or delete", %{user: user} do
      worker = %{User.worker() | company_id: user.company_id}
      %{client: client} = Flow.create_client(user)

      assert {:error, %Forbidden{}} =
               Client.create(
                 %{name: "x", owner_id: worker.id, company_id: worker.company_id},
                 as(worker)
               )

      assert {:ok, []} = Client.list_for_company(user.company_id, as(worker))
      assert {:error, %Forbidden{}} = Client.soft_delete(client, as(worker))
    end

    test "an admin creates clients owned by nobody but themselves", %{user: user} do
      assert {:error, %Forbidden{}} =
               Client.create(
                 %{name: "x", owner_id: Ash.UUID.generate(), company_id: user.company_id},
                 as(user)
               )
    end

    test "an admin of another company cannot list or delete the company's clients, whatever tenant it passes",
         %{user: user} do
      %{client: client} = Flow.create_client(user)
      stranger = User.admin()
      in_their_tenant = [actor: stranger, tenant: user.company_id]

      assert {:ok, []} = Client.list_for_company(user.company_id, in_their_tenant)
      assert {:error, _refused} = Client.soft_delete(client, in_their_tenant)
      assert {:ok, [_still_there]} = Client.list_for_company(user.company_id, as(user))
    end

    test "a host policy that applies to an action binds the server actor too: Ash checks it before the bypass",
         %{user: user} do
      assert {:error, %Forbidden{}} =
               Client.create(%{name: "x", owner_id: user.id, company_id: user.company_id},
                 actor: ServerActor.new(),
                 tenant: user.company_id
               )
    end
  end

  describe "a client brought over from another OAuth server" do
    test "keeps authenticating with its existing bcrypt secret" do
      owner = User.admin()
      zelo_secret = 42 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
      zelo_uid = 21 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)

      {:ok, _imported} =
        Client.import(
          %{
            name: "Imported from Zelo",
            client_id: zelo_uid,
            client_secret_hash: Bcrypt.hash_pwd_salt(zelo_secret),
            scopes: ["read", "write"],
            owner_id: owner.id,
            company_id: owner.company_id
          },
          actor: ServerActor.new(),
          tenant: owner.company_id
        )

      assert %{"scope" => "read write", "access_token" => access_token} =
               zelo_uid |> Flow.token_basic(zelo_secret) |> Flow.json()

      assert Flow.authenticates?(access_token)
      assert Flow.token_post(zelo_uid, zelo_secret).status == 200
      assert Flow.token_basic(zelo_uid, "wrong").status == 401
    end
  end
end
