defmodule ApiGatehouse do
  @moduledoc """
  An OAuth 2.0 authorization server for machine-to-machine API access in Ash
  and Phoenix apps: the `client_credentials` grant with client secrets, the
  `refresh_token` grant with rotation, idle expiry and replay detection, RFC 7009
  revocation, and bearer authentication for the host's API. The README walks
  through wiring it up.

  ## Pieces

    * `ApiGatehouse.Server` — the behaviour the host implements: where the
      resources are and how a client's owner is loaded.
    * `ApiGatehouse.OAuth.ClientFragment` and
      `ApiGatehouse.OAuth.AccessTokenFragment` — Ash resource fragments for the
      host's client and token tables.
    * `ApiGatehouse.Plug.Server`, `ApiGatehouse.Plug.Token`,
      `ApiGatehouse.Plug.Revocation`, `ApiGatehouse.Plug.Bearer` and
      `ApiGatehouse.Plug.RateLimit` — the router side.
    * `ApiGatehouse.ReadOnlyScopePolicy` (and `.Resource`) — keeps tokens
      without `write` away from create, update and destroy actions.
    * `ApiGatehouse.OAuth.ServerActor` — the actor the library's own lookups
      run as, which the host grants its owner lookup.

  ## Design

  Tokens are opaque and stored only as SHA-256 hashes; client secrets only as
  bcrypt hashes, compatible with `Bcrypt.hash_pwd_salt/1`. Every grant and every
  API request re-reads the token and the client and calls
  `c:ApiGatehouse.Server.load_owner/2` — nothing is cached — so revocation,
  client deletion and owner demotion take effect on the next request. No token,
  secret or hash is ever logged.

  The credentials are siloed: their own tables and verification path, separate
  from any other OAuth server the host runs (such as `mcp_gatehouse`'s), so a
  token issued by one never authenticates at the other.
  """
end
