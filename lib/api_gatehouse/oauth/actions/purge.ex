defmodule ApiGatehouse.OAuth.Actions.Purge do
  @moduledoc """
  Destroys the token rows that stopped mattering before the `before` argument:
  revoked before it, or with both the access token and any refresh token
  expired before it.

  Replay detection needs a rotated row for as long as its refresh token could
  have been presented, so pass a `before` at least
  `c:ApiGatehouse.Server.refresh_idle_ttl/0` in the past; a refresh token whose
  row is gone is merely unknown.
  """
  use Ash.Resource.Actions.Implementation

  alias Ash.ActionInput

  require Ash.Query

  @impl true
  @spec run(ActionInput.t(), keyword(), Ash.Resource.Actions.Implementation.Context.t()) ::
          :ok | {:error, term()}
  def run(input, _opts, context) do
    before = ActionInput.get_argument(input, :before)

    input.resource
    |> Ash.Query.filter(
      (not is_nil(revoked_at) and revoked_at < ^before) or
        (expires_at < ^before and (is_nil(refresh_expires_at) or refresh_expires_at < ^before))
    )
    |> Ash.bulk_destroy(
      :destroy,
      %{},
      Ash.Context.to_opts(context,
        strategy: [:atomic, :atomic_batches, :stream],
        return_errors?: true
      )
    )
    |> purged()
  end

  defp purged(%Ash.BulkResult{status: :success}), do: :ok
  defp purged(%Ash.BulkResult{errors: [error | _more]}), do: {:error, error}
end
