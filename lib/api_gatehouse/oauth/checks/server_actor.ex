defmodule ApiGatehouse.OAuth.Checks.ServerActor do
  @moduledoc """
  True when the actor is `ApiGatehouse.OAuth.ServerActor`.

  The access token resource authorizes nothing else, the client resource
  bypasses its other policies for it, and a host grants the owner lookup with
  it:

      bypass ApiGatehouse.OAuth.Checks.ServerActor do
        authorize_if action(:get_by_id)
      end
  """
  use Ash.Policy.SimpleCheck

  alias ApiGatehouse.OAuth.ServerActor

  @impl true
  @spec describe(keyword()) :: String.t()
  def describe(_options), do: "actor is the API OAuth server"

  @impl true
  @spec match?(term(), map(), keyword()) :: boolean()
  def match?(%ServerActor{}, _context, _options), do: true
  def match?(_actor, _context, _options), do: false
end
