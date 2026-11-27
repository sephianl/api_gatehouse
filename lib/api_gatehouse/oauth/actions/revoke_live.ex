defmodule ApiGatehouse.OAuth.Actions.RevokeLive do
  @moduledoc """
  Revokes every live (not yet revoked) token whose attributes named in `by:`
  equal the action's arguments of the same names, through the `:revoke` action,
  and answers how many were live when it ran. `by:` names `:client_id`.

  The rows are never loaded: on Postgres they are revoked in one UPDATE that
  returns nothing, and no notification is sent per row. Instead
  `ApiGatehouse.BearerCache` drops every cached token of the client at once,
  and keeps them out for its longest TTL, so a client with millions of live
  tokens is revoked in constant memory.

  A row someone else revoked between the count and the write counts as revoked
  rather than failing the whole revocation: on Postgres the filtered UPDATE
  skips it, and on a data layer that streams the update it comes back as a
  stale record, which is ignored here.
  """
  use Ash.Resource.Actions.Implementation

  alias ApiGatehouse.BearerCache
  alias Ash.ActionInput
  alias Ash.Error.Changes.StaleRecord

  require Ash.Query

  @impl true
  @spec run(ActionInput.t(), keyword(), Ash.Resource.Actions.Implementation.Context.t()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def run(input, opts, context) do
    matching = Map.new(opts[:by], &{&1, ActionInput.get_argument(input, &1)})
    %{client_id: client_id} = matching
    action_opts = Ash.Context.to_opts(context)

    live =
      input.resource
      |> Ash.Query.do_filter(matching)
      |> Ash.Query.filter(is_nil(revoked_at))

    with {:ok, count} <- Ash.count(live, action_opts),
         :ok <- revoke(live, action_opts) do
      BearerCache.evict({:client_tokens, input.resource, client_id})
      {:ok, count}
    end
  end

  defp revoke(live, action_opts) do
    live
    |> Ash.bulk_update(
      :revoke,
      %{},
      Keyword.merge(action_opts,
        strategy: [:atomic, :atomic_batches, :stream],
        return_records?: false,
        return_errors?: true,
        notify?: false
      )
    )
    |> revoked()
  end

  defp revoked(%Ash.BulkResult{status: :success}), do: :ok

  defp revoked(%Ash.BulkResult{errors: errors}) do
    case Enum.reject(errors || [], &stale?/1) do
      [] -> :ok
      [error | _more] -> {:error, error}
    end
  end

  defp stale?(%StaleRecord{}), do: true
  defp stale?(%{errors: [_first | _rest] = errors}), do: Enum.all?(errors, &stale?/1)
  defp stale?(_error), do: false
end
