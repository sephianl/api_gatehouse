defmodule ApiGatehouse.OAuth.ClientSecret do
  @moduledoc """
  Hashes and checks client secrets.

  A secret this library generates is 32 random bytes
  (`ApiGatehouse.OAuth.OpaqueToken`), and is stored as its SHA-256, like a
  token and for the same reason: there is nothing to guess, so a slow hash adds
  no protection to a leaked table. What a slow hash does add is CPU per check,
  and secrets are checked on the token and revocation endpoints, before anyone
  is authenticated. At bcrypt's production cost (over 100 ms of CPU a check) a
  few hundred requests a second with made-up client ids saturate a 32-thread
  machine and stall every other request it serves.

  bcrypt hashes still verify: those of clients created by api_gatehouse 0.1.0,
  and those brought over from another server, such as the
  `Bcrypt.hash_pwd_salt/1` hashes of Zelo's homegrown OAuth server
  (`AshAuthentication.BcryptProvider`). `upgrade?/2` says when to re-encode one
  as SHA-256 once its secret has verified, which
  `ApiGatehouse.OAuth.ClientAuth` does: when the secret is at least 32 bytes
  long, as a generated one is. A shorter secret may be one a person chose, and
  keeps its slow hash.

  An unknown client is checked against a dummy SHA-256, which costs what
  checking a known client's secret does, so the answer's timing does not tell
  which client ids exist — except for clients still on bcrypt, which take
  longer until their first successful authentication upgrades them.
  """

  alias ApiGatehouse.OAuth.OpaqueToken

  @upgrade_min_bytes 32
  @dummy_hash OpaqueToken.hash("api_gatehouse: no such client")

  @doc "The stored form of a fresh secret: its SHA-256 as lowercase hex."
  @spec hash(String.t()) :: String.t()
  def hash(secret), do: OpaqueToken.hash(secret)

  @doc """
  Whether `secret` matches `hash`, a SHA-256 hex or a bcrypt hash. With no hash
  — an unknown or deleted client — it checks against a dummy and answers
  `false`.
  """
  @spec verify(term(), String.t() | nil) :: boolean()
  def verify(secret, "$2" <> _rest = hash) when is_binary(secret) do
    Bcrypt.verify_pass(secret, hash)
  rescue
    ArgumentError -> false
  end

  def verify(secret, hash) when is_binary(secret) and is_binary(hash), do: Plug.Crypto.secure_compare(hash(secret), hash)

  def verify(secret, _hash) when is_binary(secret) do
    _same_work = Plug.Crypto.secure_compare(hash(secret), @dummy_hash)
    false
  end

  def verify(_secret, _hash), do: false

  @doc """
  Whether `hash`, which `secret` has just verified against, is a bcrypt hash to
  re-encode as SHA-256: it is, when the secret is long enough to have been
  generated rather than chosen.
  """
  @spec upgrade?(String.t(), String.t()) :: boolean()
  def upgrade?(secret, "$2" <> _rest), do: byte_size(secret) >= @upgrade_min_bytes
  def upgrade?(_secret, _hash), do: false
end
