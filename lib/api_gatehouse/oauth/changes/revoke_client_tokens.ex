defmodule ApiGatehouse.OAuth.Changes.RevokeClientTokens do
  @moduledoc """
  After a client is soft-deleted, revokes every live token issued to it, as
  `ApiGatehouse.OAuth.ServerActor`, through the access token resource of the
  server named in the client resource's `api_gatehouse` section.

  A deleted client is refused by every grant and every bearer request anyway;
  revoking its tokens as well means the rows say so too, and a token cannot
  outlive its client if the client is ever restored by hand.
  """

  use Ash.Resource.Change

  alias ApiGatehouse.OAuth.ServerActor
  alias ApiGatehouse.Resource.Info
  alias Ash.Changeset

  @impl true
  @spec change(Changeset.t(), keyword(), Ash.Resource.Change.Context.t()) :: Changeset.t()
  def change(changeset, _opts, _context), do: Changeset.after_action(changeset, &revoke_tokens/2)

  @impl true
  def atomic(changeset, opts, context), do: {:ok, change(changeset, opts, context)}

  defp revoke_tokens(changeset, client) do
    tokens = Info.api_gatehouse_server!(changeset.resource).access_token_resource()

    case tokens.revoke_for_client(client.id, actor: ServerActor.new()) do
      {:ok, _revoked} -> {:ok, client}
      {:error, error} -> {:error, error}
    end
  end
end
