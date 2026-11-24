defmodule ApiGatehouse.Test.OAuth do
  @moduledoc "The host's API domain, holding the two resources built from the library's fragments."
  use Ash.Domain

  resources do
    resource ApiGatehouse.Test.Client
    resource ApiGatehouse.Test.AccessToken
    resource ApiGatehouse.Test.Owner
  end
end

defmodule ApiGatehouse.Test.Owner do
  @moduledoc """
  Stands in for the host's user resource as the destination of the client's
  `belongs_to :owner`, which `relating_to_actor(:owner)` needs. The actors
  themselves are `ApiGatehouse.Test.User` structs.
  """
  use Ash.Resource, domain: ApiGatehouse.Test.OAuth, data_layer: Ash.DataLayer.Ets

  ets do
    private? true
  end

  attributes do
    uuid_primary_key :id
  end
end

defmodule ApiGatehouse.Test.Client do
  @moduledoc """
  A host client resource: the fragment over a per-process ETS table, with
  attribute multitenancy on `company_id` and README §1's host policies, scoped
  to the actions the host's users call. `:import` is how a host would bring over
  a client from another OAuth server with its existing secret hash.
  """
  use Ash.Resource,
    domain: ApiGatehouse.Test.OAuth,
    data_layer: Ash.DataLayer.Ets,
    fragments: [ApiGatehouse.OAuth.ClientFragment]

  api_gatehouse do
    server ApiGatehouse.Test.Server
  end

  ets do
    private? true
  end

  multitenancy do
    strategy :attribute
    attribute :company_id
  end

  code_interface do
    define :import, action: :import
  end

  actions do
    create :import do
      accept [:name, :client_id, :client_secret_hash, :scopes, :owner_id, :company_id]
    end
  end

  relationships do
    belongs_to :owner, ApiGatehouse.Test.Owner, define_attribute?: false, allow_nil?: false
  end

  policies do
    policy action(:create) do
      forbid_unless actor_attribute_equals(:role, :admin)
      authorize_if relating_to_actor(:owner)
    end

    policy action([:list_for_company, :soft_delete, :read]) do
      forbid_unless actor_attribute_equals(:role, :admin)
      authorize_if expr(company_id == ^actor(:company_id))
    end

    policy action(:import) do
      authorize_if ApiGatehouse.OAuth.Checks.ServerActor
    end
  end

  # Ash.DataLayer.Verifiers.RequirePreCheckWith: ETS cannot enforce identities; Postgres hosts do.
  @spec testing_identities() :: true
  def testing_identities, do: true
end

defmodule ApiGatehouse.Test.AccessToken do
  @moduledoc """
  A host access token resource: the fragment over a per-process ETS table, plus
  `:backdate`, which only tests need, to move one of a row's timestamps into
  the past instead of waiting for it.
  """
  use Ash.Resource,
    domain: ApiGatehouse.Test.OAuth,
    data_layer: Ash.DataLayer.Ets,
    fragments: [ApiGatehouse.OAuth.AccessTokenFragment]

  ets do
    private? true
  end

  code_interface do
    define :backdate, args: [:field, :seconds]
  end

  actions do
    update :backdate do
      require_atomic? false

      argument :field, :atom,
        allow_nil?: false,
        constraints: [one_of: [:revoked_at, :expires_at, :refresh_expires_at]]

      argument :seconds, :integer, allow_nil?: false

      change fn changeset, _context ->
        field = Ash.Changeset.get_argument(changeset, :field)
        seconds = Ash.Changeset.get_argument(changeset, :seconds)

        Ash.Changeset.force_change_attribute(
          changeset,
          field,
          DateTime.shift(DateTime.utc_now(), second: -seconds)
        )
      end
    end
  end

  # Ash.DataLayer.Verifiers.RequirePreCheckWith: ETS cannot enforce identities; Postgres hosts do.
  @spec testing_identities() :: true
  def testing_identities, do: true
end
