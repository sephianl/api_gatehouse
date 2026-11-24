defmodule ApiGatehouse.OAuth.Changes.StampOnce do
  @moduledoc """
  Stamps a timestamp attribute with the current time, and only if it is still
  unset. `also:` names further attributes stamped with the same time.

  The filter is what makes the action single-use. Two concurrent requests can
  both read an unstamped row, but only one UPDATE matches it, so the loser
  fails with a stale-record error rather than rotating the same refresh token
  twice or deleting the same client twice.

  That guarantee is the data layer's filtered UPDATE: it holds on Postgres, not
  on `Ash.DataLayer.Ets`, which reads, checks and writes without a lock.

  The time is the application's clock, not the database's, like every other
  timestamp the library compares against, so the five-second replay grace
  period is measured on one clock.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Ash.Expr

  require Expr

  @impl true
  @spec change(Changeset.t(), keyword(), Ash.Resource.Change.Context.t()) :: Changeset.t()
  def change(changeset, opts, _context) do
    now = DateTime.utc_now()

    opts
    |> stamped()
    |> Enum.reduce(
      only_when_unset(changeset, opts[:attribute]),
      &Changeset.force_change_attribute(&2, &1, now)
    )
  end

  @impl true
  def atomic(changeset, opts, _context) do
    now = DateTime.utc_now()

    {:atomic, only_when_unset(changeset, opts[:attribute]), Map.new(stamped(opts), &{&1, now})}
  end

  defp stamped(opts), do: [opts[:attribute] | Keyword.get(opts, :also, [])]

  defp only_when_unset(changeset, attribute), do: Changeset.filter(changeset, Expr.expr(is_nil(^Expr.ref(attribute))))
end
