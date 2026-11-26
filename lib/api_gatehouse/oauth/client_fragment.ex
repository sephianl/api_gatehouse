defmodule ApiGatehouse.OAuth.ClientFragment do
  @moduledoc """
  An API client (an "integration" or "application"): the credentials a machine
  presents at the token endpoint, and the user its tokens act as.

  A client belongs to one company and is owned by one user, whose actor every
  token issued to it acts as. Whether that user may still own API access is
  decided per request by `c:ApiGatehouse.Server.load_owner/2`.

  The host owns the module, domain, data layer, table, policies, multitenancy and
  relationships, and names its `ApiGatehouse.Server` in the `api_gatehouse`
  section:

      defmodule MyApp.Api.Client do
        use Ash.Resource,
          domain: MyApp.Api,
          data_layer: AshPostgres.DataLayer,
          fragments: [ApiGatehouse.OAuth.ClientFragment]

        api_gatehouse do
          server MyAppWeb.ApiServer
        end

        postgres do
          table "api_clients"
          repo MyApp.Repo
        end

        policies do
          policy action(:create) do
            forbid_unless actor_attribute_equals(:role, :company_admin)
            authorize_if relating_to_actor(:owner)
          end

          policy action([:list_for_company, :soft_delete]) do
            forbid_unless actor_attribute_equals(:role, :company_admin)
            authorize_if expr(company_id == ^actor(:company_id))
          end
        end
      end

  ## Actions

    * `:create` — accepts `name`, `scopes`, `owner_id` and `company_id`;
      generates `client_id` and a secret, stores the secret's SHA-256 hash and
      returns the plaintext secret once, as `:client_secret` metadata. The
      scopes must be a subset of `c:ApiGatehouse.Server.scopes/0`.
    * `:by_client_id` — the client presenting `client_id`, deleted ones
      excluded. Ignores the tenant, so it works before anyone is authenticated.
    * `:by_id` — the client with row id `id`, deleted ones excluded. Ignores the
      tenant too.
    * `:list_for_company` — the company's clients, deleted ones excluded,
      newest first.
    * `:soft_delete` — stamps `deleted_at` (once) and revokes every live token
      issued to the client.
    * `:upgrade_secret_hash` — re-encodes a bcrypt secret hash as SHA-256,
      given the `secret` that verifies against it; the token and revocation
      endpoints call it on a client's first successful authentication. It
      refuses any other secret, so it cannot change a client's secret. Leave it
      to the server actor: a host policy covering it (such as
      `action_type(:update)`) keeps bcrypt clients on bcrypt.
    * `:read` — the primary read: every row, deleted ones included.

  The host's create flow must take `owner_id` and `company_id` from the signed-in
  user, never from what a form posts.

  ## Policies

  `ApiGatehouse.OAuth.ServerActor` bypasses every other policy — but Ash
  evaluates the resource's own policies before a fragment's, so the bypass only
  takes effect for actions none of the host's policies apply to. Scope the host
  policies to the actions its users call, as above; a host policy that also
  covers `:by_client_id` or `:by_id` (such as `always()` or
  `action_type(:read)`) must come after a copy of the bypass in the host's own
  `policies` block. Without host policies, nobody but the server actor is
  authorized for anything.
  """
  use Spark.Dsl.Fragment,
    of: Ash.Resource,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [ApiGatehouse.Resource]

  alias ApiGatehouse.OAuth.Changes.GenerateClientCredentials
  alias ApiGatehouse.OAuth.Changes.RevokeClientTokens
  alias ApiGatehouse.OAuth.Changes.StampOnce
  alias ApiGatehouse.OAuth.Changes.UpgradeSecretHash
  alias ApiGatehouse.OAuth.Checks.ServerActor
  alias ApiGatehouse.OAuth.Validations.KnownScopes

  code_interface do
    define :create, action: :create
    define :get_by_client_id, args: [:client_id], action: :by_client_id
    define :get_by_id, args: [:id], action: :by_id
    define :list_for_company, args: [:company_id], action: :list_for_company
    define :soft_delete, action: :soft_delete
    define :upgrade_secret_hash, args: [:secret], action: :upgrade_secret_hash
  end

  actions do
    create :create do
      description "Creates a client. Its secret is returned once, as the `:client_secret` metadata, and only its SHA-256 hash is stored."

      accept [:name, :scopes, :owner_id, :company_id]

      metadata :client_secret, :string, allow_nil?: false

      validate KnownScopes

      change GenerateClientCredentials
    end

    read :read do
      description "Every client row, deleted ones included."

      primary? true
    end

    read :by_client_id do
      description "Looks a client up by the client id it presents, to authenticate it. Deleted clients are not found."

      argument :client_id, :string, allow_nil?: false

      get? true
      multitenancy :bypass

      filter expr(client_id == ^arg(:client_id) and is_nil(deleted_at))
    end

    read :by_id do
      description "Looks a client up by its row id, to check a token's client still exists. Deleted clients are not found."

      argument :id, :uuid, allow_nil?: false

      get? true
      multitenancy :bypass

      filter expr(id == ^arg(:id) and is_nil(deleted_at))
    end

    read :list_for_company do
      description "A company's clients, newest first. Deleted clients are left out."

      argument :company_id, :uuid, allow_nil?: false

      filter expr(company_id == ^arg(:company_id) and is_nil(deleted_at))

      prepare build(sort: [inserted_at: :desc, id: :desc])
    end

    update :soft_delete do
      description "Deletes a client: it stops authenticating at once, and every live token issued to it is revoked."

      accept []

      change {StampOnce, attribute: :deleted_at}
      change RevokeClientTokens
    end

    update :upgrade_secret_hash do
      description "Re-encodes the client's bcrypt secret hash as SHA-256, given the secret that verifies against it. Refuses any other secret."

      accept []

      argument :secret, :string do
        allow_nil? false
        sensitive? true
        constraints trim?: false, allow_empty?: false
      end

      change UpgradeSecretHash
    end
  end

  policies do
    bypass ServerActor do
      authorize_if always()
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :name, :string do
      allow_nil? false
      public? true
      constraints max_length: 200
    end

    attribute :client_id, :string do
      description "The identifier the client presents. Generated, never chosen."
      allow_nil? false
      public? true
    end

    attribute :client_secret_hash, :string do
      description "SHA-256 hex of the client secret, or a bcrypt hash until its first use. The secret itself is never stored."
      allow_nil? false
      sensitive? true
    end

    attribute :scopes, {:array, :string} do
      allow_nil? false
      public? true
      default ["read"]
    end

    attribute :owner_id, :uuid do
      description "The user every token issued to this client acts as."
      allow_nil? false
      public? true
    end

    attribute :company_id, :uuid do
      allow_nil? false
      public? true
    end

    attribute :deleted_at, :utc_datetime_usec do
      public? true
    end

    timestamps()
  end

  identities do
    identity :unique_client_id, [:client_id], all_tenants?: true
  end
end
