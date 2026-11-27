defmodule ApiGatehouse.BearerCache do
  @moduledoc """
  Keeps the token and client rows an access token authenticated with, for
  `c:ApiGatehouse.Server.bearer_cache_ttl/0` seconds, so a busy integration
  does not cost `ApiGatehouse.Plug.Bearer` two reads on every request. The
  owner is never kept: `c:ApiGatehouse.Server.load_owner/2` still runs on every
  request.

  Any write to a token or client row through the resources' actions evicts it
  on every node, after the write commits
  (`ApiGatehouse.OAuth.Notifiers.EvictCachedToken` and `EvictCachedClient`,
  over `:pg`). Revoking every token of a client or family at once evicts the
  client's tokens in one go instead
  (`ApiGatehouse.OAuth.Actions.RevokeLive`), so that it never has to load
  them. The eviction also leaves a tombstone for the longest TTL, so a
  read that started before the write, or one answered by a read replica that
  has not seen it yet, cannot put the row back. Only rows that authenticated
  are kept, keyed by the token's SHA-256: an unknown token adds nothing, and no
  raw token is held.

  A write that bypasses the actions, such as raw SQL, and a node cut off from
  the cluster go unseen for at most the TTL.
  """
  use GenServer

  alias ApiGatehouse.OAuth.OpaqueToken

  @entries ApiGatehouse.BearerCache.Entries
  @tombstones ApiGatehouse.BearerCache.Tombstones
  @scope ApiGatehouse.BearerCache.Evictions
  @group :evictions
  @max_ttl_seconds 300
  @sweep_interval to_timeout(minute: 1)

  @typedoc """
  A cached token, by its resource and hash; every cached token of a client, by
  the client resource and row id; or the same by the token resource and the
  client's row id.
  """
  @type key ::
          {:token, Ash.Resource.t(), String.t()}
          | {:client, Ash.Resource.t(), String.t()}
          | {:client_tokens, Ash.Resource.t(), String.t()}

  @doc "The longest a server may keep rows, and so how long an eviction keeps them out."
  @spec max_ttl_seconds() :: pos_integer()
  def max_ttl_seconds, do: @max_ttl_seconds

  @doc "The `:pg` scope evictions travel in, which `ApiGatehouse.Application` starts."
  @spec scope() :: atom()
  def scope, do: @scope

  @doc """
  The token and client rows `access_token` authenticates with for `server`.

  Answers from the cache when they are there; otherwise calls `load`, and keeps
  an `{:ok, token, client}` it answers for `ttl` seconds, never past the
  token's `expires_at`, unless an eviction has tombstoned the token or its
  client. With a `ttl` of 0 it only calls `load`.
  """
  @spec fetch(module(), String.t(), non_neg_integer(), (-> {:ok, struct(), struct()} | :error)) ::
          {:ok, struct(), struct()} | :error
  def fetch(_server, _access_token, 0, load), do: load.()

  def fetch(server, access_token, ttl, load) do
    key = {:token, server.access_token_resource(), OpaqueToken.hash(access_token)}
    client_resource = server.client_resource()

    case :ets.lookup(@entries, key) do
      [{^key, {:client, ^client_resource, _client_id}, token, client, until}] ->
        served(until > now(), token, client, fn -> loaded(key, client_resource, ttl, load.()) end)

      _not_cached ->
        loaded(key, client_resource, ttl, load.())
    end
  end

  @doc """
  Drops what `key` names on this node at once, and on every other node of the
  cluster as the message reaches it, and keeps it out for the longest TTL.
  """
  @spec evict(key()) :: :ok
  def evict(key) do
    forget(key)
    Enum.each(:pg.get_members(@scope, @group), &send(&1, {__MODULE__, :evict, key}))
  end

  @doc false
  @spec start_link(term()) :: GenServer.on_start()
  def start_link(_arg), do: GenServer.start_link(__MODULE__, nil, name: __MODULE__)

  @impl GenServer
  def init(nil) do
    :ets.new(@entries, [:set, :public, :named_table, read_concurrency: true])
    :ets.new(@tombstones, [:set, :public, :named_table, read_concurrency: true])
    :ok = :pg.join(@scope, @group, self())
    schedule_sweep()
    {:ok, nil}
  end

  @impl GenServer
  def handle_info({__MODULE__, :evict, key}, state) do
    forget(key)
    {:noreply, state}
  end

  def handle_info(:sweep, state) do
    sweep(now())
    schedule_sweep()
    {:noreply, state}
  end

  defp served(true, token, client, _reload), do: {:ok, token, client}
  defp served(false, _token, _client, reload), do: reload.()

  defp loaded(key, client_resource, ttl, {:ok, token, client} = found) do
    keep({key, {:client, client_resource, client.id}, token, client, until(ttl, token)})
    found
  end

  defp loaded(_key, _client_resource, _ttl, not_found), do: not_found

  defp keep(entry), do: insert(tombstoned?(entry), entry)

  defp insert(true, _entry), do: :ok

  defp insert(false, {key, _client_key, _token, _client, _until} = entry) do
    :ets.insert(@entries, entry)
    withdraw(tombstoned?(entry), key)
  end

  defp withdraw(true, key), do: :ets.delete(@entries, key)
  defp withdraw(false, _key), do: :ok

  defp tombstoned?({{:token, resource, _hash} = key, client_key, token, _client, _until}) do
    now = now()

    tombstoned?(key, now) or tombstoned?(client_key, now) or
      tombstoned?({:client_tokens, resource, Map.get(token, :client_id)}, now)
  end

  defp tombstoned?(key, now), do: match?([{_key, until}] when until > now, :ets.lookup(@tombstones, key))

  defp until(ttl, %{expires_at: expires_at}), do: min(now() + ttl * 1000, DateTime.to_unix(expires_at, :millisecond))

  defp forget(key) do
    :ets.insert(@tombstones, {key, now() + @max_ttl_seconds * 1000})
    drop(key)
  end

  defp drop({:token, _resource, _hash} = key), do: :ets.delete(@entries, key)

  defp drop({:client, _resource, _id} = client_key), do: :ets.match_delete(@entries, {:_, client_key, :_, :_, :_})

  defp drop({:client_tokens, resource, client_id}),
    do: :ets.match_delete(@entries, {{:token, resource, :_}, :_, %{client_id: client_id}, :_, :_})

  defp sweep(now) do
    :ets.select_delete(@entries, [{{:_, :_, :_, :_, :"$1"}, [{:"=<", :"$1", now}], [true]}])
    :ets.select_delete(@tombstones, [{{:_, :"$1"}, [{:"=<", :"$1", now}], [true]}])
  end

  defp schedule_sweep, do: Process.send_after(self(), :sweep, @sweep_interval)

  defp now, do: System.system_time(:millisecond)
end
