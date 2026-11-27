defmodule ApiGatehouse.OAuth.Notifiers.EvictCachedToken do
  @moduledoc """
  Evicts a token row from `ApiGatehouse.BearerCache` once a write to it
  commits: revoking or rotating it, or a host's own update or destroy. Issuing
  one evicts nothing, since a new token cannot be cached yet. Revoking a
  family's or a client's tokens sends no notification per row;
  `ApiGatehouse.OAuth.Actions.RevokeLive` evicts them itself.
  """
  use Spark.Dsl.Extension
  use Ash.Notifier

  alias ApiGatehouse.BearerCache
  alias Ash.Notifier.Notification

  @impl Ash.Notifier
  def notify(%Notification{action: %{type: type}, resource: resource, data: %{token_hash: hash}})
      when type in [:update, :destroy], do: BearerCache.evict({:token, resource, hash})

  def notify(_issued), do: :ok
end
