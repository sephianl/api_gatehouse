defmodule ApiGatehouse.OAuth.ScopesTest do
  @moduledoc "What a token is granted: the requested scopes when all are allowed, else everything allowed, else nothing."
  use ExUnit.Case, async: true

  alias ApiGatehouse.OAuth.Scopes

  test "allowed is the intersection, in the order of the first list" do
    assert Scopes.allowed([["write", "read"], ["read", "write", "admin"]]) == ["write", "read"]
    assert Scopes.allowed([["read", "write"], ["read"], ["write", "read"]]) == ["read"]
    assert Scopes.allowed([["write"], ["read"]]) == []
  end

  test "without a scope parameter, everything allowed is granted" do
    assert Scopes.grant(nil, ["read", "write"]) == {:ok, ["read", "write"]}
    assert Scopes.grant("", ["read", "write"]) == {:ok, ["read", "write"]}
    assert Scopes.grant("   ", ["read"]) == {:ok, ["read"]}
  end

  test "a scope parameter narrows, deduplicated" do
    assert Scopes.grant("read", ["read", "write"]) == {:ok, ["read"]}
    assert Scopes.grant("write read write", ["read", "write"]) == {:ok, ["write", "read"]}
  end

  test "a scope outside what is allowed, or nothing allowed at all, is invalid_scope" do
    assert Scopes.grant("write", ["read"]) == {:error, :invalid_scope}
    assert Scopes.grant("read admin", ["read", "write"]) == {:error, :invalid_scope}
    assert Scopes.grant(nil, []) == {:error, :invalid_scope}
  end

  test "a scope parameter that is not a string is invalid_request" do
    assert Scopes.grant(["read"], ["read"]) == {:error, :invalid_request}
    assert Scopes.grant(%{"read" => true}, ["read"]) == {:error, :invalid_request}
  end
end
