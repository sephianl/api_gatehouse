defmodule ApiGatehouse.Server.CallbacksTest do
  @moduledoc """
  A host implements only what differs from the defaults, and an owner loader
  that returns nothing, or a user of another company, cannot authenticate.
  """
  use ExUnit.Case, async: true

  alias ApiGatehouse.Server.Callbacks
  alias ApiGatehouse.Test.ConfiguredServer
  alias ApiGatehouse.Test.LazyServer
  alias ApiGatehouse.Test.MinimalServer
  alias ApiGatehouse.Test.User

  test "a server implementing only the required callbacks gets every default" do
    assert Callbacks.access_token_ttl(MinimalServer) == 3600
    assert Callbacks.refresh_idle_ttl(MinimalServer) == 90 * 24 * 3600
    assert Callbacks.issue_refresh_token?(MinimalServer) == true
    assert Callbacks.scopes(MinimalServer) == ["read", "write"]
    assert Callbacks.trusted_proxies(MinimalServer) == []
  end

  test "a server's own answers win" do
    assert Callbacks.access_token_ttl(ConfiguredServer) == 600
    assert Callbacks.refresh_idle_ttl(ConfiguredServer) == 60
    assert Callbacks.issue_refresh_token?(ConfiguredServer) == true
    assert Callbacks.scopes(ConfiguredServer) == ["read"]
    assert Callbacks.trusted_proxies(ConfiguredServer) == ["130.211.0.0/22"]
  end

  test "an optional callback counts even before its module is loaded" do
    :code.purge(LazyServer)
    :code.delete(LazyServer)
    refute :erlang.module_loaded(LazyServer)

    assert Callbacks.refresh_idle_ttl(LazyServer) == 42
  end

  describe "load_owner/3" do
    test "accepts an owner of the client's company" do
      user = User.admin()

      assert {:ok, %User{id: id}} = Callbacks.load_owner(MinimalServer, user.id, user.company_id)
      assert id == user.id
    end

    test "refuses an error, nil, or an owner of another company" do
      company_id = Ash.UUID.generate()

      for owner_id <- [User.unloadable_id(), User.loads_as_nil_id(), User.in_other_company_id()] do
        assert Callbacks.load_owner(MinimalServer, owner_id, company_id) == :error
      end
    end

    test "accepts an actor without a company key" do
      assert {:ok, %{id: _id}} =
               Callbacks.load_owner(MinimalServer, User.without_company_id(), Ash.UUID.generate())
    end
  end
end
