defmodule ApiGatehouse.OAuth.OpaqueToken do
  @moduledoc """
  The one generator for every random value this authorization server hands out —
  client ids, client secrets, access and refresh tokens — and the one place that
  hashes tokens for storage.

  Access and refresh tokens are stored only as their hash. A bearer secret is
  compared, never read back, so there is nothing to decrypt and a leaked table is
  not a set of usable credentials. The hash is unsalted deliberately: the row has
  to be findable from the presented value alone, and 32 random bytes leave
  nothing to guess. Client secrets are stored the same way; see
  `ApiGatehouse.OAuth.ClientSecret`.

  Tokens stay opaque rather than becoming JWTs so revocation is immediate: a
  request reads the row, or a cached copy that revoking it evicts, rather than
  trusting a signature until it expires.
  """

  @bytes 32

  @doc "A fresh random value of `bytes` bytes (32 by default), URL-safe base64 without padding."
  @spec generate(pos_integer()) :: String.t()
  def generate(bytes \\ @bytes), do: bytes |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)

  @doc """
  The stored form of a token: its SHA-256 as lowercase hex.

  Hex rather than base64 so Postgres' own `encode(sha256(...), 'hex')` produces
  identical values: a host can backfill hashes in SQL — for example when
  migrating plaintext tokens — and tokens issued before such a migration keep
  working across it.
  """
  @spec hash(String.t()) :: String.t()
  def hash(secret), do: :sha256 |> :crypto.hash(secret) |> Base.encode16(case: :lower)
end
