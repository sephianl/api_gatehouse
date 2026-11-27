defmodule ApiGatehouse.BearerCacheTest do
  @moduledoc """
  A token's rows are kept only while nothing has written to them: never past
  the TTL or the token's own expiry, never once an eviction for the token or
  its client has gone by, and never under the raw token.
  """
  use ExUnit.Case, async: true

  alias ApiGatehouse.BearerCache
  alias ApiGatehouse.OAuth.OpaqueToken
  alias ApiGatehouse.Test.AccessToken
  alias ApiGatehouse.Test.Client
  alias ApiGatehouse.Test.Server

  @entries ApiGatehouse.BearerCache.Entries

  defp rows(expires_in_ms \\ 3_600_000) do
    {%{expires_at: DateTime.add(DateTime.utc_now(), expires_in_ms, :millisecond)}, %{id: Ash.UUID.generate()}}
  end

  defp fetch(access_token, {token, client}, ttl \\ 60) do
    BearerCache.fetch(Server, access_token, ttl, fn ->
      send(self(), :loaded)
      {:ok, token, client}
    end)
  end

  defp token_key(access_token), do: {:token, AccessToken, OpaqueToken.hash(access_token)}

  defp access_token, do: OpaqueToken.generate()

  test "keeps what the loader found for the TTL, and nothing it did not find" do
    {token, client} = rows = rows()
    presented = access_token()

    assert fetch(presented, rows) == {:ok, token, client}
    assert_received :loaded
    assert fetch(presented, rows) == {:ok, token, client}
    refute_received :loaded

    missing = access_token()
    assert BearerCache.fetch(Server, missing, 60, fn -> :error end) == :error
    assert :ets.lookup(@entries, token_key(missing)) == []
  end

  test "a TTL of 0 asks the loader every time" do
    rows = rows()
    presented = access_token()

    fetch(presented, rows, 0)
    fetch(presented, rows, 0)

    assert_received :loaded
    assert_received :loaded
  end

  test "keeps nothing past the token's own expiry" do
    rows = rows(20)
    presented = access_token()

    fetch(presented, rows)
    assert_received :loaded
    Process.sleep(30)
    fetch(presented, rows)

    assert_received :loaded
  end

  test "an evicted token is dropped, and kept out for the longest TTL" do
    rows = rows()
    presented = access_token()
    fetch(presented, rows)
    assert_received :loaded

    BearerCache.evict(token_key(presented))
    fetch(presented, rows)
    fetch(presented, rows)

    assert_received :loaded
    assert_received :loaded
  end

  test "evicting a client drops every token it has cached, and keeps them out" do
    {_token, client} = rows = rows()
    {other_token, other_client} = rows()
    [first, second, unrelated] = [access_token(), access_token(), access_token()]
    fetch(first, rows)
    fetch(second, rows)
    fetch(unrelated, {other_token, other_client})

    BearerCache.evict({:client, Client, client.id})

    assert :ets.lookup(@entries, token_key(first)) == []
    assert :ets.lookup(@entries, token_key(second)) == []
    assert [_kept] = :ets.lookup(@entries, token_key(unrelated))

    fetch(first, rows)
    assert :ets.lookup(@entries, token_key(first)) == []
  end

  test "a row read before an eviction is not kept after it" do
    {token, client} = rows()
    presented = access_token()

    loaded_then_evicted = fn ->
      BearerCache.evict(token_key(presented))
      {:ok, token, client}
    end

    assert BearerCache.fetch(Server, presented, 60, loaded_then_evicted) == {:ok, token, client}
    assert :ets.lookup(@entries, token_key(presented)) == []
  end

  test "an eviction reaches every member of the group, as on the other nodes" do
    :ok = :pg.join(BearerCache.scope(), :evictions, self())
    key = token_key(access_token())

    BearerCache.evict(key)

    assert_receive {BearerCache, :evict, ^key}
  end

  test "an eviction from another node is applied" do
    rows = rows()
    presented = access_token()
    fetch(presented, rows)

    send(BearerCache, {BearerCache, :evict, token_key(presented)})
    :sys.get_state(BearerCache)

    assert :ets.lookup(@entries, token_key(presented)) == []
  end

  test "keeps the token's hash, never the token" do
    presented = access_token()
    fetch(presented, rows())

    assert :binary.match(:erlang.term_to_binary(:ets.tab2list(@entries)), presented) == :nomatch
  end

  test "a sweep drops entries that have ended" do
    presented = access_token()
    fetch(presented, rows(1))
    Process.sleep(5)

    send(BearerCache, :sweep)
    :sys.get_state(BearerCache)

    assert :ets.lookup(@entries, token_key(presented)) == []
  end
end
