defmodule ApiGatehouse.OAuth.AccessTokenTest do
  @moduledoc """
  The access token fragment's actions. What reaches the data layer is the hash,
  and the raw tokens are returned exactly once; lookups by access token find
  live rows only; rotation and revocation are single-use at the data layer;
  family and client revocation reach exactly their rows; purge removes only
  rows that stopped mattering; and nobody but the server actor touches a row.
  """
  use ExUnit.Case, async: true

  alias ApiGatehouse.OAuth.OpaqueToken
  alias ApiGatehouse.OAuth.ServerActor
  alias ApiGatehouse.Test.AccessToken
  alias ApiGatehouse.Test.Flow
  alias ApiGatehouse.Test.User
  alias Ash.Error.Changes.StaleRecord
  alias Ash.Error.Forbidden
  alias Ash.Error.Invalid

  @server_actor [actor: ServerActor.new()]

  setup do
    user = User.admin()

    Map.put(Flow.create_client(user), :user, user)
  end

  describe "issue" do
    test "stores hashes, never the tokens, and returns the tokens once", %{client: client} do
      issued = Flow.issue(client)
      %{access_token: access_token, refresh_token: refresh_token} = issued.__metadata__

      [row] = Flow.rows()

      assert row.token_hash == OpaqueToken.hash(access_token)
      assert row.refresh_token_hash == OpaqueToken.hash(refresh_token)
      refute Map.has_key?(row.__metadata__, :access_token)
      refute Map.has_key?(row.__metadata__, :refresh_token)
      refute inspect(row) =~ row.token_hash
    end

    test "no stored value is a raw token, however the token was issued", %{
      client_id: client_id,
      secret: secret
    } do
      first = client_id |> Flow.token_basic(secret) |> Flow.json()
      second = client_id |> Flow.refresh(secret, first["refresh_token"]) |> Flow.json()

      stored =
        Enum.flat_map(Flow.rows(), fn row ->
          row
          |> Map.from_struct()
          |> Map.drop([:__meta__, :__metadata__, :__lateral_join_source__, :__order__])
          |> Map.values()
        end)

      for value <- Enum.flat_map([first, second], &[&1["access_token"], &1["refresh_token"]]) do
        refute Enum.any?(stored, &(is_binary(&1) and &1 =~ value))
      end
    end

    test "sets the expiries from its arguments", %{client: client} do
      row = Flow.issue(client, expires_in: 120, refresh_expires_in: 7200)

      assert_in_delta DateTime.diff(row.expires_at, DateTime.utc_now()), 120, 5
      assert_in_delta DateTime.diff(row.refresh_expires_at, DateTime.utc_now()), 7200, 5
    end

    test "without refresh_expires_in, issues no refresh token", %{client: client} do
      row = Flow.issue(client, refresh_expires_in: nil)

      assert row.__metadata__.refresh_token == nil
      assert row.refresh_token_hash == nil
      assert row.refresh_expires_at == nil
    end

    test "tokens are 32 random bytes, URL-safe, and the hash is Postgres-compatible hex SHA-256" do
      tokens = for _token <- 1..50, do: OpaqueToken.generate()

      assert length(Enum.uniq(tokens)) == 50
      assert Enum.all?(tokens, &(&1 =~ ~r/\A[A-Za-z0-9_-]{43}\z/))

      assert OpaqueToken.hash("abc") ==
               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    end
  end

  describe "lookups" do
    test "resolve from the values the client holds", %{client: client} do
      issued = Flow.issue(client)

      assert {:ok, %{id: id}} =
               AccessToken.get_by_access_token(issued.__metadata__.access_token, @server_actor)

      assert id == issued.id

      assert {:ok, %{id: ^id}} =
               AccessToken.get_by_refresh_token(issued.__metadata__.refresh_token, @server_actor)
    end

    test "by access token finds live rows only; by refresh token finds any", %{client: client} do
      expired = Flow.issue(client)
      Flow.backdate(expired, :expires_at, 1)
      revoked = Flow.issue(client)
      {:ok, _revoked} = AccessToken.revoke(revoked, @server_actor)

      for row <- [expired, revoked] do
        assert {:error, _not_found} =
                 AccessToken.get_by_access_token(row.__metadata__.access_token, @server_actor)

        assert {:ok, _found} =
                 AccessToken.get_by_refresh_token(row.__metadata__.refresh_token, @server_actor)
      end
    end

    test "an unknown token finds nothing" do
      assert {:error, _not_found} = AccessToken.get_by_access_token("not-a-token", @server_actor)
      assert {:error, _not_found} = AccessToken.get_by_refresh_token("not-a-token", @server_actor)
    end
  end

  describe "single use" do
    test "a row cannot be rotated twice from a stale read", %{client: client} do
      row = Flow.issue(client)

      assert {:ok, rotated} = AccessToken.rotate(row, @server_actor)
      assert rotated.rotated_at
      assert rotated.revoked_at == rotated.rotated_at
      assert {:error, %Invalid{errors: [%StaleRecord{}]}} = AccessToken.rotate(row, @server_actor)
    end

    test "a row cannot be revoked twice, nor rotated once revoked", %{client: client} do
      row = Flow.issue(client)

      assert {:ok, revoked} = AccessToken.revoke(row, @server_actor)
      assert is_nil(revoked.rotated_at)
      assert {:error, %Invalid{errors: [%StaleRecord{}]}} = AccessToken.revoke(row, @server_actor)
      assert {:error, %Invalid{errors: [%StaleRecord{}]}} = AccessToken.rotate(row, @server_actor)
    end
  end

  describe "revoke_family and revoke_for_client" do
    test "a family is the live rows of one client, owner and company", %{
      client: client,
      user: user
    } do
      live = Flow.issue(client)
      second = Flow.issue(client)
      already = Flow.issue(client)
      {:ok, _revoked} = AccessToken.revoke(already, @server_actor)
      other_owner = Flow.issue(client, owner_id: Ash.UUID.generate())
      other_company = Flow.issue(client, company_id: Ash.UUID.generate())
      %{client: other_client} = Flow.create_client(user)
      other = Flow.issue(other_client)

      assert {:ok, 2} =
               AccessToken.revoke_family(
                 client.id,
                 client.owner_id,
                 client.company_id,
                 @server_actor
               )

      revoked = for row <- Flow.rows(), row.revoked_at, into: MapSet.new(), do: row.id
      assert revoked == MapSet.new([live.id, second.id, already.id])
      refute Enum.any?([other_owner, other_company, other], &MapSet.member?(revoked, &1.id))
    end

    test "revoke_for_client reaches every live row of the client and nothing else", %{
      client: client,
      user: user
    } do
      Flow.issue(client)
      Flow.issue(client, owner_id: Ash.UUID.generate())
      %{client: other_client} = Flow.create_client(user)
      other = Flow.issue(other_client)

      assert {:ok, 2} = AccessToken.revoke_for_client(client.id, @server_actor)
      assert {:ok, 0} = AccessToken.revoke_for_client(client.id, @server_actor)
      assert is_nil(Flow.row_for_access(other.__metadata__.access_token).revoked_at)
    end
  end

  describe "purge" do
    test "destroys rows revoked or fully expired before the cutoff, and nothing else", %{
      client: client
    } do
      day = 24 * 3600

      revoked_long_ago = Flow.issue(client)
      {:ok, revoked_long_ago} = AccessToken.revoke(revoked_long_ago, @server_actor)
      Flow.backdate(revoked_long_ago, :revoked_at, 100 * day)

      revoked_recently = Flow.issue(client)
      {:ok, _revoked} = AccessToken.revoke(revoked_recently, @server_actor)

      expired_long_ago = Flow.issue(client)

      expired_long_ago
      |> Flow.backdate(:expires_at, 100 * day)
      |> Flow.backdate(:refresh_expires_at, 95 * day)

      expired_without_refresh = Flow.issue(client, refresh_expires_in: nil)
      Flow.backdate(expired_without_refresh, :expires_at, 100 * day)

      refresh_still_live = Flow.issue(client)
      Flow.backdate(refresh_still_live, :expires_at, 100 * day)

      refresh_expired_recently = Flow.issue(client)

      refresh_expired_recently
      |> Flow.backdate(:expires_at, 100 * day)
      |> Flow.backdate(:refresh_expires_at, 10 * day)

      live = Flow.issue(client)

      assert :ok =
               AccessToken.purge(
                 DateTime.shift(DateTime.utc_now(), second: -90 * day),
                 @server_actor
               )

      assert MapSet.new(Flow.rows(), & &1.id) ==
               MapSet.new([
                 revoked_recently.id,
                 refresh_still_live.id,
                 refresh_expired_recently.id,
                 live.id
               ])
    end
  end

  describe "authorization" do
    test "only the server actor issues, reads, finds, rotates, revokes or purges", %{
      client: client,
      user: user
    } do
      attrs = %{
        client_id: client.id,
        owner_id: user.id,
        company_id: user.company_id,
        scopes: ["read"],
        expires_in: 60
      }

      assert {:error, %Forbidden{}} = AccessToken.issue(attrs, actor: user)
      assert {:error, %Forbidden{}} = AccessToken.issue(attrs)

      row = Flow.issue(client)

      for actor <- [user, nil] do
        assert {:ok, []} = AccessToken.read(actor: actor)

        assert {:error, _not_found} =
                 AccessToken.get_by_access_token(row.__metadata__.access_token, actor: actor)

        assert {:error, %Forbidden{}} = AccessToken.rotate(row, actor: actor)
        assert {:error, %Forbidden{}} = AccessToken.revoke(row, actor: actor)
        assert {:error, %Forbidden{}} = AccessToken.revoke_for_client(client.id, actor: actor)
        assert {:error, %Forbidden{}} = AccessToken.purge(DateTime.utc_now(), actor: actor)
      end

      assert [%{revoked_at: nil}] = Flow.rows()
    end
  end
end
