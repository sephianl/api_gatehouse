defmodule ApiGatehouse.ReadOnlyScopePolicy.Resource do
  @moduledoc """
  `ApiGatehouse.ReadOnlyScopePolicy` for one resource rather than a whole domain:
  keeps an API token without the `write` scope away from the resource's create,
  update and destroy actions.

      use Ash.Resource,
        authorizers: [Ash.Policy.Authorizer],
        fragments: [ApiGatehouse.ReadOnlyScopePolicy.Resource]

  It adds one policy, which applies only to a write on an API token lacking
  `write` and then forbids it; the resource's own policies still decide every
  request, and an action none of them covers stays forbidden.
  """
  use Spark.Dsl.Fragment, of: Ash.Resource, authorizers: [Ash.Policy.Authorizer]

  alias ApiGatehouse.Checks.TokenLacksWriteScope

  policies do
    policy [TokenLacksWriteScope, action_type([:create, :update, :destroy])] do
      forbid_if always()
    end
  end
end
