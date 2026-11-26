defmodule ApiGatehouse.OAuth.Actions.RevokeLive do
  @moduledoc """
  Revokes every live (not yet revoked) token whose attributes named in `by:`
  equal the action's arguments of the same names, through the `:revoke` action,
  and answers how many it revoked. It asks for a notification per row, which a
  bulk update does not send by default, so `ApiGatehouse.BearerCache` drops
  each revoked token.

  A row someone else revoked between the read and the write counts as revoked
  rather than failing the whole revocation: on Postgres the filtered UPDATE
  skips it, and on a data layer that streams the update it comes back as a
  stale record, which is ignored here.
  """
  use Ash.Resource.Actions.Implementation

  alias Ash.ActionInput
  alias Ash.Error.Changes.StaleRecord

  require Ash.Query

  @impl true
  @spec run(ActionInput.t(), keyword(), Ash.Resource.Actions.Implementation.Context.t()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def run(input, opts, context) do
    matching = Map.new(opts[:by], &{&1, ActionInput.get_argument(input, &1)})

    input.resource
    |> Ash.Query.do_filter(matching)
    |> Ash.Query.filter(is_nil(revoked_at))
    |> Ash.bulk_update(
      :revoke,
      %{},
      Ash.Context.to_opts(context,
        strategy: [:atomic, :atomic_batches, :stream],
        return_records?: true,
        return_errors?: true,
        notify?: true
      )
    )
    |> revoked()
  end

  defp revoked(%Ash.BulkResult{status: :success, records: records}), do: {:ok, length(records || [])}

  defp revoked(%Ash.BulkResult{errors: errors, records: records}) do
    case Enum.reject(errors || [], &stale?/1) do
      [] -> {:ok, length(records || [])}
      [error | _more] -> {:error, error}
    end
  end

  defp stale?(%StaleRecord{}), do: true
  defp stale?(%{errors: [_first | _rest] = errors}), do: Enum.all?(errors, &stale?/1)
  defp stale?(_error), do: false
end
