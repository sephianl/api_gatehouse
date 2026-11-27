defmodule ApiGatehouse.OAuth.ClientSecretTest do
  @moduledoc """
  A client secret the library generates is stored as its SHA-256, the form
  tokens are stored in. bcrypt hashes brought over from another server
  (`Bcrypt.hash_pwd_salt/1`) still verify, and are marked for upgrade when the
  secret is long enough to be machine-generated.
  """
  use ExUnit.Case, async: true

  alias ApiGatehouse.OAuth.ClientSecret
  alias ApiGatehouse.OAuth.OpaqueToken

  test "hashes a fresh secret as its SHA-256 hex, and verifies it and nothing else" do
    hash = ClientSecret.hash("s3cret")

    assert hash == OpaqueToken.hash("s3cret")
    assert ClientSecret.verify("s3cret", hash)
    refute ClientSecret.verify("s3cret!", hash)
    refute ClientSecret.verify(String.upcase(hash), hash)
    refute ClientSecret.verify(nil, hash)
    refute ClientSecret.verify(["s3cret"], hash)
  end

  test "verifies a hash made by Bcrypt.hash_pwd_salt/1, as AshAuthentication.BcryptProvider makes them" do
    hash = Bcrypt.hash_pwd_salt("from-zelo")

    assert ClientSecret.verify("from-zelo", hash)
    refute ClientSecret.verify("from-zelo!", hash)
    refute ClientSecret.verify(nil, hash)
  end

  test "without a hash, or with one it does not recognise, fails" do
    refute ClientSecret.verify("anything", nil)
    refute ClientSecret.verify(nil, nil)
    refute ClientSecret.verify("anything", "")
    refute ClientSecret.verify("anything", "$2b$garbage")
    refute ClientSecret.verify("anything", "plaintext")
  end

  test "a bcrypt hash of a machine-length secret is due an upgrade; a short secret's is not, nor SHA-256" do
    generated = OpaqueToken.generate()
    short = "a human chose this"

    assert ClientSecret.upgrade?(generated, Bcrypt.hash_pwd_salt(generated))
    refute ClientSecret.upgrade?(short, Bcrypt.hash_pwd_salt(short))
    refute ClientSecret.upgrade?(generated, ClientSecret.hash(generated))
  end
end
