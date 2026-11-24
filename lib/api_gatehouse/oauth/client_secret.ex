defmodule ApiGatehouse.OAuth.ClientSecret do
  @moduledoc """
  Hashes and checks client secrets with bcrypt.

  bcrypt rather than SHA-256 because a client secret is long-lived and is
  checked once per token request, not once per API call, so its cost is
  affordable — and because the secrets of Zelo's homegrown OAuth server are
  stored as bcrypt hashes (`AshAuthentication.BcryptProvider`, which is
  `Bcrypt.hash_pwd_salt/1`), which keep working unchanged.

  `verify/2` takes the same time whether or not a client was found, so the token
  endpoint does not tell an attacker which client ids exist.
  """

  @doc "The bcrypt hash of a fresh secret."
  @spec hash(String.t()) :: String.t()
  def hash(secret), do: Bcrypt.hash_pwd_salt(secret)

  @doc """
  Whether `secret` matches `hash`. With no hash — an unknown or deleted client —
  it runs a dummy check of the same cost and answers `false`.
  """
  @spec verify(term(), String.t() | nil) :: boolean()
  def verify(secret, hash) when is_binary(secret) and is_binary(hash), do: Bcrypt.verify_pass(secret, hash)

  def verify(_secret, _hash), do: Bcrypt.no_user_verify()
end
