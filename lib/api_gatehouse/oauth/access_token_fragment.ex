defmodule ApiGatehouse.OAuth.AccessTokenFragment do
  @moduledoc """
  An opaque API access token and, optionally, its refresh token, issued to one
  client and acting as that client's owner within its company.

  Only the SHA-256 of each token is stored, so the raw tokens exist exactly
  once — in the `:issue` response, as the `:access_token` and `:refresh_token`
  action metadata. There is no column holding them to read back later.

  A refresh rotates: the presented row is revoked (and marked `rotated_at`) and a
  new row issued, so each refresh token works once, and each carries its own
  `refresh_expires_at`. A token *family* is every row sharing a client, owner and
  company; presenting a revoked refresh token again revokes the whole family
  (see `ApiGatehouse.Plug.Token`).

  The host owns the module, domain, data layer, table and any foreign keys on
  `client_id`, `owner_id` and `company_id` (declare them with
  `define_attribute?: false`). Every action is authorized for
  `ApiGatehouse.OAuth.ServerActor` only; the host adds no policies, and no
  multitenancy: rows are read before any tenant is known.

  ## Actions

    * `:issue` — accepts `client_id` (the client's row id), `owner_id`,
      `company_id` and `scopes`; arguments `expires_in` (seconds) and
      `refresh_expires_in` (seconds, or `nil` for no refresh token).
    * `:by_access_token` — the live (unrevoked, unexpired) row for a raw access
      token.
    * `:by_refresh_token` — the row for a raw refresh token, whatever its state,
      so a replay can be recognised.
    * `:rotate` — revokes a row as rotated, only if it is not revoked yet.
    * `:revoke` — revokes a row, only if it is not revoked yet.
    * `:revoke_family` — revokes every live row of a client, owner and company;
      answers how many.
    * `:revoke_for_client` — revokes every live row of a client; answers how
      many.
    * `:purge` — destroys rows revoked, or fully expired, before `before`.
    * `:read` — the primary read: every row.
  """
  use Spark.Dsl.Fragment,
    of: Ash.Resource,
    authorizers: [Ash.Policy.Authorizer],
    notifiers: [ApiGatehouse.OAuth.Notifiers.EvictCachedToken]

  alias ApiGatehouse.OAuth.Actions.Purge
  alias ApiGatehouse.OAuth.Actions.RevokeLive
  alias ApiGatehouse.OAuth.Changes.GenerateTokens
  alias ApiGatehouse.OAuth.Changes.StampOnce
  alias ApiGatehouse.OAuth.Checks.ServerActor
  alias ApiGatehouse.OAuth.Preparations.HashedLookup

  code_interface do
    define :read, action: :read
    define :issue, action: :issue
    define :get_by_access_token, args: [:access_token], action: :by_access_token
    define :get_by_refresh_token, args: [:refresh_token], action: :by_refresh_token
    define :rotate, action: :rotate
    define :revoke, action: :revoke
    define :revoke_family, args: [:client_id, :owner_id, :company_id], action: :revoke_family
    define :revoke_for_client, args: [:client_id], action: :revoke_for_client
    define :purge, args: [:before], action: :purge
  end

  actions do
    create :issue do
      description "Issues an access token and, unless `refresh_expires_in` is nil, a refresh token. The raw tokens are returned once, as metadata."

      accept [:client_id, :owner_id, :company_id, :scopes]

      argument :expires_in, :integer, allow_nil?: false, constraints: [min: 1]
      argument :refresh_expires_in, :integer, constraints: [min: 1]

      metadata :access_token, :string, allow_nil?: false
      metadata :refresh_token, :string

      change GenerateTokens
    end

    read :read do
      description "Every token row, unfiltered. Present so loads and bulk actions have a primary read; authenticating a request goes through `by_access_token`."

      primary? true
    end

    read :by_access_token do
      description "Looks a live token up by the hash of its access token, to authenticate one API request."

      argument :access_token, :string, allow_nil?: false, sensitive?: true

      get? true

      prepare {HashedLookup, argument: :access_token, attribute: :token_hash}

      filter expr(is_nil(revoked_at) and expires_at > now())
    end

    read :by_refresh_token do
      description "Looks a token up by the hash of its refresh token, to rotate it. Revoked and expired rows are found too, so a replay can be recognised."

      argument :refresh_token, :string, allow_nil?: false, sensitive?: true

      get? true

      prepare {HashedLookup, argument: :refresh_token, attribute: :refresh_token_hash}
    end

    update :rotate do
      description "Spends a row's refresh token: revokes the row as rotated, and only if it was not revoked yet, so a refresh token rotates once."

      accept []

      change {StampOnce, attribute: :revoked_at, also: [:rotated_at]}
    end

    update :revoke do
      description "Revokes a row, and only if it was not revoked yet."
      primary? true

      accept []

      change {StampOnce, attribute: :revoked_at}
    end

    action :revoke_family, :integer do
      description "Revokes every live token of one family — a client, an owner and a company — and answers how many."

      argument :client_id, :uuid, allow_nil?: false
      argument :owner_id, :uuid, allow_nil?: false
      argument :company_id, :uuid, allow_nil?: false

      run {RevokeLive, by: [:client_id, :owner_id, :company_id]}
    end

    action :revoke_for_client, :integer do
      description "Revokes every live token issued to a client, and answers how many."

      argument :client_id, :uuid, allow_nil?: false

      run {RevokeLive, by: [:client_id]}
    end

    action :purge do
      description "Destroys every row revoked before `before`, or whose access token and refresh token both expired before it."

      argument :before, :utc_datetime_usec, allow_nil?: false

      run Purge
    end

    destroy :destroy do
      description "Removes one row, for `purge`."

      primary? true
    end
  end

  policies do
    policy always() do
      authorize_if ServerActor
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :token_hash, :string do
      description "SHA-256 of the access token. The token itself is never stored."
      allow_nil? false
      sensitive? true
    end

    attribute :refresh_token_hash, :string do
      description "SHA-256 of the refresh token, if one was issued. The token itself is never stored."
      sensitive? true
    end

    attribute :scopes, {:array, :string}, allow_nil?: false, public?: true

    attribute :client_id, :uuid do
      description "The row id (not the public client id) of the client the token was issued to."
      allow_nil? false
      public? true
    end

    attribute :owner_id, :uuid, allow_nil?: false, public?: true
    attribute :company_id, :uuid, allow_nil?: false, public?: true
    attribute :expires_at, :utc_datetime_usec, allow_nil?: false, public?: true
    attribute :refresh_expires_at, :utc_datetime_usec, public?: true
    attribute :revoked_at, :utc_datetime_usec, public?: true

    attribute :rotated_at, :utc_datetime_usec do
      description "When the refresh token was spent on a refresh. Set together with `revoked_at`."
      public? true
    end

    timestamps()
  end

  identities do
    identity :unique_token_hash, [:token_hash]
    identity :unique_refresh_token_hash, [:refresh_token_hash]
  end
end
