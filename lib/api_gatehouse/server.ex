defmodule ApiGatehouse.Server do
  @moduledoc """
  The host's adapter: the one module through which every library plug reaches
  what belongs to the host.

  Every library plug reaches it through `ApiGatehouse.Plug.Server` earlier in the
  pipeline (or its own `server:` option), and the client resource names it in
  its `api_gatehouse` section. Name it on the pipeline, not on routes: see
  `ApiGatehouse.Plug.Server` for the compile-time dependency a route's `server:`
  creates. The library never decides which users may own API access, which
  tenant a client belongs to or which tables hold the OAuth rows — it asks this
  module.

  Optional callbacks are resolved at call time, never in a plug's `init/1`, so a
  production router that compiles its pipelines does not freeze them into the
  build. See `ApiGatehouse.Server.Callbacks` for the defaults.
  """

  @doc "The host resource built from `ApiGatehouse.OAuth.ClientFragment`."
  @callback client_resource() :: Ash.Resource.t()

  @doc "The host resource built from `ApiGatehouse.OAuth.AccessTokenFragment`."
  @callback access_token_resource() :: Ash.Resource.t()

  @doc """
  Loads the actor a client's tokens act as: the client's owner, within the
  client's company.

  Called on every grant and every bearer request, so a demoted or removed owner
  loses API access on the next request. It MUST load within the tenant
  `company_id` (for example with `tenant: company_id`) and decide whether the
  user may still own API access — for example "is still a company admin of that
  company". Return `{:error, reason}` otherwise. The library also refuses
  `{:ok, nil}` and an actor whose `:company_id` differs from `company_id`.
  """
  @callback load_owner(owner_id :: String.t(), company_id :: String.t()) ::
              {:ok, actor :: term()} | {:error, term()}

  @doc "Seconds an access token stays valid. Defaults to 3600."
  @callback access_token_ttl() :: pos_integer()

  @doc """
  Seconds a refresh token may sit unused before it expires. Every rotation
  issues a new refresh token with a fresh expiry. Defaults to 90 days.
  """
  @callback refresh_idle_ttl() :: pos_integer()

  @doc """
  Whether the token endpoint issues refresh tokens and accepts the
  `refresh_token` grant. Defaults to `true`.
  """
  @callback issue_refresh_token?() :: boolean()

  @doc """
  Every scope a token can carry. A client's own scopes must be a subset of these,
  and a token is only ever granted scopes in both lists. Defaults to
  `["read", "write"]`.
  """
  @callback scopes() :: [String.t()]

  @doc "Proxy addresses or CIDR ranges trusted to append to `X-Forwarded-For`. Defaults to `[]`."
  @callback trusted_proxies() :: [String.t()]

  @doc """
  Seconds `ApiGatehouse.Plug.Bearer` may keep the token and client rows an
  access token authenticated with, rather than read them again. Defaults to 0,
  reading them on every request; at most 300.

  The owner is still loaded on every request. A write to a token or client
  through the resources' actions evicts it on every connected node at once;
  one that bypasses them, such as raw SQL, or a node cut off from the cluster,
  goes unseen for up to this long. See `ApiGatehouse.BearerCache`.
  """
  @callback bearer_cache_ttl() :: non_neg_integer()

  @optional_callbacks access_token_ttl: 0,
                      refresh_idle_ttl: 0,
                      issue_refresh_token?: 0,
                      scopes: 0,
                      trusted_proxies: 0,
                      bearer_cache_ttl: 0
end
