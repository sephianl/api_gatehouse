defmodule ApiGatehouse.OAuth.Changes.GenerateClientCredentials do
  @moduledoc """
  Assigns a new client the identifier it will present from then on and a fresh
  secret, stores only the secret's SHA-256 hash, and returns the secret as
  `:client_secret` action metadata — the one and only time it is readable.

  Both are generated here rather than accepted, so nobody chooses a client's
  identity or a guessable secret.
  """

  use Ash.Resource.Change

  alias ApiGatehouse.OAuth.ClientSecret
  alias ApiGatehouse.OAuth.OpaqueToken
  alias Ash.Changeset

  @client_id_bytes 16

  @impl true
  @spec change(Changeset.t(), keyword(), Ash.Resource.Change.Context.t()) :: Changeset.t()
  def change(changeset, _opts, _context) do
    secret = OpaqueToken.generate()

    changeset
    |> Changeset.force_change_attribute(:client_id, OpaqueToken.generate(@client_id_bytes))
    |> Changeset.before_action(&Changeset.force_change_attribute(&1, :client_secret_hash, ClientSecret.hash(secret)))
    |> Changeset.after_action(fn _changeset, client ->
      {:ok, Ash.Resource.put_metadata(client, :client_secret, secret)}
    end)
  end
end
