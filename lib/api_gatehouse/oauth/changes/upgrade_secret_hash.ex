defmodule ApiGatehouse.OAuth.Changes.UpgradeSecretHash do
  @moduledoc """
  Re-encodes a client's bcrypt secret hash as the SHA-256 of the `:secret`
  argument, which must verify against it and be long enough to upgrade
  (`ApiGatehouse.OAuth.ClientSecret.upgrade?/2`). Any other secret is an error,
  so the action can never change which secret a client has, only how it is
  stored.

  The UPDATE is filtered on the hash that was checked. Should the secret change
  in between — a host's own rotation action, say — the UPDATE matches no row
  and fails as stale, instead of writing the old secret back over the new one.
  """

  use Ash.Resource.Change

  alias ApiGatehouse.OAuth.ClientSecret
  alias Ash.Changeset
  alias Ash.Expr

  require Expr

  @impl true
  @spec change(Changeset.t(), keyword(), Ash.Resource.Change.Context.t()) :: Changeset.t()
  def change(changeset, _opts, _context) do
    case upgraded_hash(changeset) do
      {:ok, hash} ->
        changeset
        |> still_unchanged()
        |> Changeset.force_change_attribute(:client_secret_hash, hash)

      :error ->
        refused(changeset)
    end
  end

  @impl true
  def atomic(changeset, _opts, _context) do
    case upgraded_hash(changeset) do
      {:ok, hash} -> {:atomic, still_unchanged(changeset), %{client_secret_hash: hash}}
      :error -> {:ok, refused(changeset)}
    end
  end

  defp upgraded_hash(changeset) do
    secret = Changeset.get_argument(changeset, :secret)
    current = changeset.data.client_secret_hash

    if is_binary(secret) and is_binary(current) and ClientSecret.upgrade?(secret, current) and
         ClientSecret.verify(secret, current),
       do: {:ok, ClientSecret.hash(secret)},
       else: :error
  end

  defp still_unchanged(changeset),
    do: Changeset.filter(changeset, Expr.expr(client_secret_hash == ^changeset.data.client_secret_hash))

  defp refused(changeset),
    do: Changeset.add_error(changeset, field: :secret, message: "is not a secret to upgrade this client's hash with")
end
