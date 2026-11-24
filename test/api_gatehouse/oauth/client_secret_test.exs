defmodule ApiGatehouse.OAuth.ClientSecretTest do
  @moduledoc """
  Client secrets are bcrypt hashes compatible with `Bcrypt.hash_pwd_salt/1`, and
  checking against no hash at all runs the same work and fails.
  """
  use ExUnit.Case, async: true

  alias ApiGatehouse.OAuth.ClientSecret

  test "verifies the secret it hashed, and nothing else" do
    hash = ClientSecret.hash("s3cret")

    assert "$2b$" <> _rest = hash
    assert ClientSecret.verify("s3cret", hash)
    refute ClientSecret.verify("s3cret!", hash)
    refute ClientSecret.verify(nil, hash)
    refute ClientSecret.verify(["s3cret"], hash)
  end

  test "verifies a hash made by Bcrypt.hash_pwd_salt/1, as AshAuthentication.BcryptProvider makes them" do
    assert ClientSecret.verify("from-zelo", Bcrypt.hash_pwd_salt("from-zelo"))
  end

  test "without a hash, does the dummy work and fails" do
    refute ClientSecret.verify("anything", nil)
    refute ClientSecret.verify(nil, nil)
  end
end
