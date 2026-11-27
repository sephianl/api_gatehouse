defmodule ApiGatehouse.OAuth.Notifiers.EvictCachedClient do
  @moduledoc """
  Evicts every cached token of a client from `ApiGatehouse.BearerCache` once a
  write to the client commits: deleting it, re-encoding its secret hash, or a
  host's own update or destroy. Creating one evicts nothing.
  """
  use Spark.Dsl.Extension
  use Ash.Notifier

  alias ApiGatehouse.BearerCache
  alias Ash.Notifier.Notification

  @impl Ash.Notifier
  def notify(%Notification{action: %{type: type}, resource: resource, data: %{id: id}}) when type in [:update, :destroy],
    do: BearerCache.evict({:client, resource, id})

  def notify(_created), do: :ok
end
