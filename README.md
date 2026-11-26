# api_gatehouse

An OAuth 2.0 authorization server for **machine-to-machine API access** in Ash
and Phoenix apps: a customer's system (an ERP, a BI export, a script) gets API
credentials from an admin screen in your app and exchanges them for short-lived
bearer tokens.

- **Token endpoint** — the `client_credentials` grant, with the client secret
  in HTTP Basic (`client_secret_basic`) or the body (`client_secret_post`), and
  the `refresh_token` grant with rotation, idle expiry and replay detection.
- **RFC 7009 revocation** of access and refresh tokens.
- **Bearer authentication** — a plug that sets the Ash actor (the client's
  owner), tenant (the client's company) and context (the token's scopes) for
  your AshJsonApi or AshGraphql endpoints.
- **Ash resource fragments** for clients and tokens, in your own tables.
- **A read-only scope policy** — keeps tokens without `write` away from create,
  update and destroy actions.
- **Rate limiting** of the token and revocation endpoints by client address.

The library owns protocol and security behaviour. Your app owns the tables,
users, admin screen, policies and the decision who may own API access.

This is not an official Ash project.

## When to use it

| | api_gatehouse | [mcp_gatehouse](https://github.com/sephianl/mcp_gatehouse) |
|---|---|---|
| Caller | a machine your customer runs | an AI model in an MCP client |
| Credentials | client id + secret an admin creates in your app | dynamic client registration, no secret |
| Grants | `client_credentials`, `refresh_token` | `authorization_code` + PKCE, `refresh_token` |
| Consent | none: the client acts as its owner | a human approves on a consent page |
| Endpoint protected | your API (JSON:API, GraphQL) | `/mcp` |

Both libraries share their design — opaque tokens stored as SHA-256 hashes, a
host adapter module, Ash fragments for host-owned tables, the owner reloaded on
every request — but they are deliberately separate servers with separate
tables: a token from one never authenticates at the other.

Use api_gatehouse when a customer's system needs OAuth `client_credentials`
access to your API (customers often insist on OAuth over plain API keys), and
you want:

- tokens, refresh tokens and client secrets stored only as SHA-256 hashes;
- revocation, client deletion and owner demotion to take effect on the next
  request — every request reloads the token, the client and the owner;
- tokens that act as a real user of yours, within that user's company, so your
  existing Ash policies decide what an integration may do.

The data model assumes multi-tenancy: every client belongs to an `owner_id`
user and a `company_id` (both UUIDs). A single-tenant app can use one fixed
company id.

## Installation

```elixir
def deps do
  [
    {:api_gatehouse, github: "sephianl/api_gatehouse", tag: "v0.2.0"},
    {:simple_sat, "~> 0.1"}
  ]
end
```

- The resources' actions are policy-authorized, so Ash needs a SAT solver at
  runtime: `simple_sat` or `picosat_elixir`, without `only:`.
- Client secrets stored as bcrypt hashes (by api_gatehouse 0.1.0, or brought
  over from another server) are checked with `bcrypt_elixir`, which builds a
  NIF: the build machine needs `make` and a C compiler.
- Add `:api_gatehouse` to `import_deps` in `.formatter.exs` for the
  `api_gatehouse do server ... end` section to format without parentheses.

## Wiring it up

### 1. Resources

Two resources over the library's fragments, in a domain of your own:

```elixir
defmodule MyApp.Api do
  use Ash.Domain

  resources do
    resource MyApp.Api.Client
    resource MyApp.Api.AccessToken
  end
end

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

    references do
      reference :owner, on_delete: :delete
      reference :company, on_delete: :delete
    end
  end

  multitenancy do
    strategy :attribute
    attribute :company_id
  end

  relationships do
    belongs_to :owner, MyApp.Accounts.User, define_attribute?: false, allow_nil?: false
    belongs_to :company, MyApp.Accounts.Company, define_attribute?: false, allow_nil?: false
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

defmodule MyApp.Api.AccessToken do
  use Ash.Resource,
    domain: MyApp.Api,
    data_layer: AshPostgres.DataLayer,
    fragments: [ApiGatehouse.OAuth.AccessTokenFragment]

  postgres do
    table "api_access_tokens"
    # The primary, not a replica: a lagging replica would hide a just-issued token.
    repo MyApp.Repo

    references do
      reference :client, on_delete: :delete, index?: true
    end
  end

  relationships do
    belongs_to :client, MyApp.Api.Client, define_attribute?: false, allow_nil?: false
  end
end
```

Generate the migration with `mix ash.codegen add_api_oauth`.

**Client** (`ApiGatehouse.OAuth.ClientFragment`) has `name`, `client_id`,
`client_secret_hash`, `scopes`, `owner_id`, `company_id`, `deleted_at` and
timestamps, and these actions (code interface in brackets):

| action | what it does |
|---|---|
| `:create` (`create/2`) | Accepts `name`, `scopes` (default `["read"]`), `owner_id`, `company_id`. Generates `client_id` and a secret; stores only the secret's SHA-256 hash; returns the secret **once**, as `client.__metadata__.client_secret`. Scopes must be a subset of the server's `scopes/0`. |
| `:list_for_company` (`list_for_company/2`) | A company's clients, deleted ones excluded, newest first. |
| `:soft_delete` (`soft_delete/2`) | Stamps `deleted_at` (once) and revokes every live token of the client. |
| `:by_client_id` (`get_by_client_id/2`) | Live client by its public client id, ignoring the tenant. Used by the library. |
| `:by_id` (`get_by_id/2`) | Live client by row id, ignoring the tenant. Used by the library. |
| `:upgrade_secret_hash` (`upgrade_secret_hash/3`) | Re-encodes a bcrypt `client_secret_hash` as SHA-256, given the secret that verifies against it; refuses any other secret. Used by the library on a bcrypt client's first successful authentication; keep host policies off it. |
| `:read` | Primary read, deleted clients included. |

**Access token** (`ApiGatehouse.OAuth.AccessTokenFragment`) has `token_hash`,
`refresh_token_hash`, `scopes`, `client_id` (the client's row id), `owner_id`,
`company_id`, `expires_at`, `refresh_expires_at`, `revoked_at`, `rotated_at`
and timestamps; its actions `:issue`, `:by_access_token`, `:by_refresh_token`,
`:rotate`, `:revoke`, `:revoke_family`, `:revoke_for_client` and `:purge` are
for the library (and your purge job) only. Add no policies and no multitenancy
to it: tokens are read before any tenant is known, and every action is
authorized for `ApiGatehouse.OAuth.ServerActor` alone.

**Policies on the client resource.** The library looks clients up as
`ApiGatehouse.OAuth.ServerActor`, which the fragment lets through with a
`bypass`. Ash evaluates a resource's own policies *before* a fragment's, so
that bypass only helps for actions none of your policies apply to: scope your
policies to the actions your users call, as above. If you write a broader
policy — `always()`, `action_type(:read)` — start your `policies` block with a
copy of the bypass:

```elixir
policies do
  bypass ApiGatehouse.OAuth.Checks.ServerActor do
    authorize_if always()
  end

  policy action_type(:read) do
    authorize_if expr(company_id == ^actor(:company_id))
  end
end
```

Without any policies of yours, nobody but the library can use the client
actions.

**Owner and company come from the signed-in user.** `:create` accepts
`owner_id` and `company_id`; set them from the current user, never from form
input. The policies above let a company admin create clients owned by
themselves only, and list and delete only their own company's clients,
whatever tenant is passed. `load_owner/2` loads the owner within the client's
company, so a client created for a user of another company never
authenticates either.

### 2. Owner lookup

Every grant and every API request loads the client's owner through your
`load_owner/2`, before anyone is authenticated, as
`ApiGatehouse.OAuth.ServerActor`. Grant exactly that lookup on your user
resource, **before** any policy that requires the actor to belong to a company:

```elixir
policies do
  bypass ApiGatehouse.OAuth.Checks.ServerActor do
    authorize_if action(:get_by_id)
  end

  # ... existing policies
end
```

`ServerActor` is its own struct, not a user with a reserved role, so no stored
account can ever hold it.

### 3. Server module

One module implements `ApiGatehouse.Server`; every plug and the client actions
reach your app through it.

```elixir
defmodule MyAppWeb.ApiServer do
  @behaviour ApiGatehouse.Server

  alias ApiGatehouse.OAuth.ServerActor
  alias MyApp.Accounts.User

  @impl true
  def client_resource, do: MyApp.Api.Client

  @impl true
  def access_token_resource, do: MyApp.Api.AccessToken

  @impl true
  def load_owner(owner_id, company_id) do
    case User.get_by_id(owner_id, actor: ServerActor.new(), tenant: company_id) do
      {:ok, %User{role: :company_admin, archived_at: nil} = user} -> {:ok, user}
      {:ok, _no_longer_allowed} -> {:error, :not_a_company_admin}
      {:error, error} -> {:error, error}
    end
  end
end
```

| callback | |
|---|---|
| `client_resource/0`, `access_token_resource/0` | Your resources from step 1. |
| `load_owner/2` | Loads the actor a client's tokens act as, on every grant and every API request. Must load within the tenant `company_id` and decide whether the user may (still) own API access; `{:error, reason}` otherwise. `{:ok, nil}` and an actor of another company are refused too. |

Optional callbacks:

| callback | default |
|---|---|
| `access_token_ttl/0` | `3600` — seconds an access token is valid |
| `refresh_idle_ttl/0` | 90 days, in seconds — how long a refresh token may sit unused; every rotation starts a new period |
| `issue_refresh_token?/0` | `true` — `false` issues no refresh tokens and refuses the refresh grant |
| `scopes/0` | `["read", "write"]` — every scope a token can carry |
| `trusted_proxies/0` | `[]` — addresses or CIDR ranges trusted to append to `X-Forwarded-For`. The header is read only when the socket peer is one of these or a private/loopback address |

### 4. Router

```elixir
pipeline :api_oauth do
  plug ApiGatehouse.Plug.Server, server: MyAppWeb.ApiServer
  plug :accepts, ["json"]
end

pipeline :api_oauth_token do
  plug ApiGatehouse.Plug.RateLimit, bucket: "api_oauth_token", limit: 20
end

pipeline :api_oauth_revoke do
  plug ApiGatehouse.Plug.RateLimit, bucket: "api_oauth_revoke", limit: 30
end

pipeline :api do
  plug ApiGatehouse.Plug.Server, server: MyAppWeb.ApiServer
  plug :accepts, ["json"]
  plug ApiGatehouse.Plug.Bearer
end

scope "/api/oauth" do
  pipe_through [:api_oauth, :api_oauth_token]

  post "/token", ApiGatehouse.Plug.Token, []
end

scope "/api/oauth" do
  pipe_through [:api_oauth, :api_oauth_revoke]

  post "/revoke", ApiGatehouse.Plug.Revocation, []
end

scope "/api" do
  pipe_through :api

  forward "/json", MyAppWeb.JsonApiRouter
end
```

- **Name the server on the pipeline, not on routes.**
  `ApiGatehouse.Plug.Server` puts it on the connection for the plugs after it.
  Phoenix compiles route plug options into the router, so `server:` on a route
  would make the router depend on your resources at compile time.
- **Route plugs need the `[]` third argument** in Phoenix.
- **Ordering:** the `/api/oauth` scopes come before any `/api` catch-all.
- **Rate limits:** each `RateLimit` names its own `bucket`, keyed on the client
  address — an IPv6 caller by its /64 — which trusts `X-Forwarded-For` only
  when the request arrives from a `trusted_proxies/0` or private/loopback
  address, and then only as far as those proxies go (see
  `ApiGatehouse.ClientIp`). List your load balancer in `trusted_proxies/0`:
  behind an untrusted ingress every caller shares one bucket. Options:
  `bucket:` (required), `limit:` (required), `period:` in ms (default 60 000).
- **Other API endpoints** (`forward "/gql", Absinthe.Plug, ...`) go in the same
  `:api` scope. AshJsonApi and AshGraphql read the actor, tenant and context
  `Bearer` sets.
- **Body parsing:** the endpoint must parse urlencoded bodies (and JSON, if you
  accept it at the token endpoint).
- **Other credentials:** `Bearer` answers 401 to anything that is not a live
  token. An API that also accepts other credentials calls
  `ApiGatehouse.Plug.Bearer.authenticate/2`, which decides the same way but
  sends nothing.

What `Bearer` puts on an authenticated request:

| | |
|---|---|
| Ash actor | the owner, as `load_owner/2` returned it |
| Ash tenant | the client's `company_id` |
| Ash context | `%{api_gatehouse: %{scopes: [...], client_id: "..."}}`, also under `:shared` so nested actions see it; an upstream key of that name is replaced |
| `conn.assigns.api_gatehouse_token` | the token row |
| `conn.assigns.api_gatehouse_client` | the client row |

A host plug after `Bearer` can add its own context, such as `api?: true`, with
`Ash.PlugHelpers.update_context/2`.

### 5. Managing clients

Your admin screen calls the client actions as the signed-in user:

```elixir
{:ok, client} =
  MyApp.Api.Client.create(
    %{name: "ERP sync", scopes: ["read"], owner_id: user.id, company_id: user.company_id},
    actor: user,
    tenant: user.company_id
  )

# Show these once; the secret cannot be recovered.
client.client_id
client.__metadata__.client_secret

{:ok, clients} = MyApp.Api.Client.list_for_company(user.company_id, actor: user, tenant: user.company_id)

{:ok, _deleted} = MyApp.Api.Client.soft_delete(client, actor: user, tenant: user.company_id)
```

Translate the labels you show for the scopes yourself; the library only knows
`"read"` and `"write"`.

### 6. Scopes and the read-only policy

A client has a subset of `scopes/0`. A token request may narrow it with the
`scope` parameter; asking for a scope the client does not have is
`invalid_scope`. Without `scope`, the token gets all of the client's scopes.

Reads are never restricted by scope. `write` is enforced by
`ApiGatehouse.ReadOnlyScopePolicy`, which forbids create, update and destroy
actions for a token without `write`, and does nothing for requests that did
not come in on an API token. Add it to every domain your API serves:

```elixir
use Ash.Domain, fragments: [ApiGatehouse.ReadOnlyScopePolicy]
```

or to a single resource, with `ApiGatehouse.ReadOnlyScopePolicy.Resource`.

> **Ash gotcha:** a domain-level policy only applies to resources whose own
> `authorizers` include `Ash.Policy.Authorizer`. For any other resource of the
> domain the policy silently does nothing — Ash warns at compile time
> (fatal under `--warnings-as-errors`). Give every resource of such a domain
> `authorizers: [Ash.Policy.Authorizer]` and policies covering every action type
> it serves.

Generic actions are not covered, since only their resource knows whether they
write. A write they run through `Ash.Context.to_opts/2` is still refused,
because `Bearer` puts the scopes in the shared context. Forbid a generic action
that writes by other means yourself:

```elixir
policy [ApiGatehouse.Checks.TokenLacksWriteScope, action(:import_orders)] do
  forbid_if always()
end
```

### 7. Purging old tokens

Token rows are never deleted by the library. Purge the ones that stopped
mattering from a periodic job (Oban cron, for example):

```elixir
cutoff = DateTime.add(DateTime.utc_now(), -90, :day)
:ok = MyApp.Api.AccessToken.purge(cutoff, actor: ApiGatehouse.OAuth.ServerActor.new())
```

It destroys rows revoked before the cutoff, and rows whose access token and
refresh token both expired before it. Keep the cutoff at least
`refresh_idle_ttl/0` in the past: replay detection needs a rotated row for as
long as its refresh token could still have been presented.

### 8. Config

```elixir
# Phoenix's default filter is ["password", "token"]; without "secret" a
# client_secret posted to the token endpoint lands in the router's debug log.
config :phoenix, :filter_parameters, ["password", "secret", "token"]

# config/test.exs: cheap bcrypt in tests that import clients with bcrypt hashes.
config :bcrypt_elixir, log_rounds: 4
```

In tests, point `config :api_gatehouse, :rate_limiter` at a stub with Hammer's
`hit/3`, or the suite shares one real bucket per address.

### 9. Tests worth having in your app

The library's own suite runs on `Ash.DataLayer.Ets`, which cannot prove single
use under concurrency. On your real data layer:

- two concurrent refreshes of one refresh token yield exactly one 200;
- `load_owner/2` resolves an owner in, and only in, the client's company, and
  refuses a demoted one;
- a company admin cannot list or delete another company's clients.

### 10. Security logging

The library logs almost nothing on its own. What happens at the token and
revocation endpoints is reported as `:telemetry` events instead — tokens
issued, requests refused, refresh-token replays, revocations and rate-limit
denials — each with the trusted client address and user agent, so you decide
what to keep and for how long. Every event is listed in
`ApiGatehouse.Telemetry`; none carries a secret, a token or the connection.

```elixir
# In your application's start/2:
:telemetry.attach_many(
  "my-app-api-security-log",
  ApiGatehouse.Telemetry.events(),
  &MyApp.ApiSecurityLog.handle_event/4,
  nil
)

defmodule MyApp.ApiSecurityLog do
  require Logger

  def handle_event([:api_gatehouse | event], _measurements, metadata, _config) do
    Logger.info("api_gatehouse #{Enum.join(event, ".")}", Map.to_list(metadata))
  end
end
```

The address is personal data: keep these logs for a fixed, short period.

## Protocol reference

Token request (`POST /api/oauth/token`, `application/x-www-form-urlencoded` or
JSON):

```
Authorization: Basic base64(urlencode(client_id) ":" urlencode(client_secret))

grant_type=client_credentials&scope=read
```

or `client_id` and `client_secret` in the body instead of the header — never
both (`invalid_request`). Credentials in the query string are ignored. A
refresh sends `grant_type=refresh_token&refresh_token=...` with the same client
authentication, and optionally a narrower `scope`.

Success (RFC 6749 §5.1, `Cache-Control: no-store`):

```json
{"access_token": "...", "token_type": "Bearer", "expires_in": 3600, "scope": "read", "refresh_token": "..."}
```

Errors (§5.2) are `{"error": ..., "error_description": ...}`:

| error | status | when |
|---|---|---|
| `invalid_request` | 400 | missing `grant_type`, `refresh_token` or `token`; both authentication methods; non-string `scope` |
| `invalid_client` | 401 | missing, unknown or deleted client; wrong secret; owner no longer loads. `WWW-Authenticate: Basic realm="oauth"` when HTTP Basic was used |
| `invalid_grant` | 400 | refresh token unknown, expired, revoked, rotated, or issued to another client |
| `unauthorized_client` | 400 | refresh grant while `issue_refresh_token?/0` is false |
| `unsupported_grant_type` | 400 | any other grant type |
| `invalid_scope` | 400 | a scope the client (or the refreshed token) does not have |
| `server_error` | 500 | a token row could not be written; logged without any secret |

Revocation (`POST /api/oauth/revoke`, RFC 7009): the same client
authentication, `token` (access or refresh token) and optional
`token_type_hint`. Answers 200 with an empty body whether or not the token
existed or belonged to the client; only the client's own tokens are revoked.
Revoking either token of a pair revokes both.

API requests send `Authorization: Bearer <access_token>`. A rejection is 401
`{"error": "invalid_token"}` with `WWW-Authenticate: Bearer error="invalid_token"`,
or with a bare `WWW-Authenticate: Bearer` when no bearer token was sent.

## Refresh tokens

Every refresh rotates: the presented refresh token is spent (its row revoked
and marked `rotated_at`, which also ends its access token) and a new pair
issued, with a fresh `refresh_idle_ttl/0`. A refresh token left unused that
long expires.

A revoked refresh token presented again more than five seconds after its
revocation revokes every live token of its family — the client, its owner and
company — and is refused. Within five seconds it is treated as the client's own
concurrent retry and only refused. Since a refresh needs the client secret too,
whoever replays a refresh token holds both; the client can always get a new
token with its credentials.

## Migrating from Zelo's OAuth server

- **Clients.** `oauth_applications` maps onto the client table, keeping each
  row's `id` (tokens refer to it): `uid` →
  `client_id`, `secret` → `client_secret_hash` unchanged (both are
  `Bcrypt.hash_pwd_salt/1` hashes, so existing secrets keep working; each is
  re-encoded as SHA-256 on its first successful authentication), `scopes`
  `"read write"` → `string_to_array(scopes, ' ')`, `owner_id` kept,
  `company_id` from the owner's company, `deleted_at` kept. `redirect_uri` is
  dropped.
- **Tokens.** Zelo stores access and refresh tokens in plaintext. Either let
  every integration get a new token (they hold their secrets; old tokens stop
  working at cutover), or hash them in a data migration and drop the plaintext
  columns in the same deploy:

  ```sql
  INSERT INTO api_access_tokens (id, token_hash, refresh_token_hash, scopes, client_id, owner_id,
                                 company_id, expires_at, refresh_expires_at, revoked_at,
                                 inserted_at, updated_at)
  SELECT t.id,
         encode(sha256(convert_to(t.token, 'UTF8')), 'hex'),
         encode(sha256(convert_to(t.refresh_token, 'UTF8')), 'hex'),
         string_to_array(t.scopes, ' '),
         t.application_id, t.resource_owner_id, u.company_id,
         t.inserted_at + make_interval(secs => coalesce(t.expires_in, 3600)),
         CASE WHEN t.refresh_token IS NOT NULL THEN now() + interval '90 days' END,
         t.revoked_at, t.inserted_at, t.updated_at
  FROM oauth_access_tokens t JOIN users u ON u.id = t.resource_owner_id;
  ```

  `ApiGatehouse.OAuth.OpaqueToken.hash/1` is that same lowercase hex SHA-256.
- **Behaviour integrations will notice:** a refresh now needs the client
  credentials; `token_type` is `"Bearer"` (was `"bearer"`); the response no
  longer carries `scopes`, `created_at`, `jti` or `created_from_*`; a `scope`
  naming a scope the client lacks is `invalid_scope` (Zelo silently dropped
  it); revocation needs client authentication. Mount
  `ApiGatehouse.Plug.Revocation` at `DELETE /api/oauth/tokens` too to keep
  Zelo's path.
- **Policies:** Zelo's context key was `oauth_scopes` (a string); it is now
  `api_gatehouse.scopes` (a list). Zelo's read-only policy also forbade generic
  actions; add the policy from step 6 for the ones that write.

## Security notes

- Access tokens, refresh tokens and client secrets are 32 random bytes,
  returned once, stored only as SHA-256 hashes. With nothing to guess, a slow
  hash would protect nothing; it would only make each unauthenticated request
  to the token endpoint cost a bcrypt check, which a flood turns into a whole
  machine's CPU.
- bcrypt secret hashes — from api_gatehouse 0.1.0 or another server — still
  verify, and are re-encoded as SHA-256 on the client's first successful
  authentication when the secret is at least 32 bytes. A shorter secret may be
  one a person chose, and stays on bcrypt.
- An unknown client id costs the same check as a wrong secret, so the token
  endpoint does not reveal which client ids exist — except that a client
  still on bcrypt answers slower until it is upgraded.
- Rate limits key on an address the caller cannot pick: `X-Forwarded-For` is
  read only from a trusted peer, walked from the right past trusted proxies,
  and an IPv6 caller counts per /64. Expired keys are swept every minute.
- Every grant and every API request re-reads the token and the client and calls
  `load_owner/2`: nothing is cached. A deleted client, a revoked token and a
  demoted owner fail on the next request.
- The refresh grant requires client authentication, and the refresh token must
  belong to the authenticated client (RFC 6749 §6).
- No token, secret or hash is logged by the library. The only log lines are a
  warning when a replayed refresh token revokes a family, a warning when a
  bcrypt secret hash could not be re-encoded, and an error when a
  token row cannot be written, naming the public client id, owner and company.
  Everything else is a telemetry event (step 10), which carries no secret or
  token either.
- The tenant a token reaches is the client's company, fixed at creation.

## Upgrading from 0.1.0

- **Client secrets** are stored as SHA-256 from now on. Existing bcrypt hashes
  keep working and are re-encoded on each client's next successful
  authentication through the new `:upgrade_secret_hash` action, which only the
  server actor may run: keep host policies off it. The hash is 64 characters,
  where bcrypt's was 60.
- **`X-Forwarded-For` is read only from a trusted peer**: a private or loopback
  address, or one in `trusted_proxies/0`. If your ingress reaches the app from
  anywhere else, list it, or every caller shares one rate-limit bucket.
- **Rate limits** key an IPv6 caller by its /64, and `ApiGatehouse.ClientIp`
  has `rate_limit_key/2` for hosts that count other endpoints the same way.
- **Telemetry events** report the token and revocation endpoints (step 10).

## Limitations

- No `private_key_jwt` or mTLS client authentication; no JWT access tokens; no
  token introspection endpoint (RFC 7662) or discovery document (RFC 8414).
- No action to rotate a client's secret: create a new client and delete the old
  one.
- No absolute refresh lifetime: a token family lives as long as it keeps
  refreshing within the idle TTL.
- Scopes are flat strings; only `write` has library-enforced meaning.

## Development

```sh
mix deps.get
mix format --check-formatted
MIX_ENV=test mix compile --warnings-as-errors
mix test
mix credo --strict
mix dialyzer
```

## License

MIT — see [LICENSE](LICENSE).
