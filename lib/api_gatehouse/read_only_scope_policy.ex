defmodule ApiGatehouse.ReadOnlyScopePolicy do
  @moduledoc """
  Keeps an API token without the `write` scope away from create, update and
  destroy actions, in every domain it is added to.

      use Ash.Domain, fragments: [ApiGatehouse.ReadOnlyScopePolicy]

  For a single resource, use `ApiGatehouse.ReadOnlyScopePolicy.Resource`
  instead.

  It only ever forbids, and only requests that came in through
  `ApiGatehouse.Plug.Bearer` (see `ApiGatehouse.Checks.TokenLacksWriteScope`);
  every other request is untouched. Authorizing here would let a read-only
  token through actions no resource policy grants. Reads are never restricted:
  there is no separate check for `read`.

  ## Only resources with the policy authorizer

  A domain policy only reaches resources whose own `authorizers` include
  `Ash.Policy.Authorizer`, so this fragment does nothing for a resource without
  it. Ash warns at compile time — fatal under `--warnings-as-errors` — for every
  resource of a domain carrying domain policies that lacks the authorizer
  (the policy authorizer's `VerifyResources` verifier). Give each such resource
  the authorizer and policies covering the action types it serves:

      use Ash.Resource, authorizers: [Ash.Policy.Authorizer]

  An action type no policy covers is then forbidden for everyone.

  ## Generic actions

  Generic actions (`action :name do ... end`) are not covered: a generic action
  may read or write, and only its resource knows which. Ash passes the token's
  context on to the actions a generic action runs through `Ash.Context.to_opts/2`,
  so the writes it delegates are still refused; for a generic action that writes
  by other means, forbid it in the host's own policies:

      policy [ApiGatehouse.Checks.TokenLacksWriteScope, action(:import_orders)] do
        forbid_if always()
      end
  """
  use Spark.Dsl.Fragment, of: Ash.Domain, extensions: [Ash.Policy.Authorizer]

  alias ApiGatehouse.Checks.TokenLacksWriteScope

  policies do
    policy [TokenLacksWriteScope, action_type([:create, :update, :destroy])] do
      forbid_if always()
    end
  end
end
