defmodule ApiGatehouse.ReadOnlyScopePolicyTest do
  @moduledoc """
  A token granted only `read` cannot create, update or destroy in a domain or
  resource carrying the policy, also through a generic action that runs a write
  with its context passed on, while reads and generic actions themselves stay
  open; a token with `write` and requests that did not come in on an API token
  are untouched.
  """
  use ExUnit.Case, async: true

  alias ApiGatehouse.Checks.TokenLacksWriteScope
  alias ApiGatehouse.Test.Flow
  alias ApiGatehouse.Test.Gadget
  alias ApiGatehouse.Test.User
  alias ApiGatehouse.Test.Widget
  alias Ash.Error.Forbidden

  setup do
    user = User.admin()
    {:ok, widget} = Widget.create("sprocket", actor: user)

    %{user: user, widget: widget}
  end

  defp as_token(user, scopes) do
    gatehouse = %{scopes: scopes, client_id: "client"}

    [actor: user, context: %{api_gatehouse: gatehouse, shared: %{api_gatehouse: gatehouse}}]
  end

  defp widget_names(user) do
    {:ok, widgets} = Widget.list(actor: user)

    widgets |> Enum.map(& &1.name) |> Enum.sort()
  end

  describe "on a domain" do
    test "a read-only token cannot create, update or destroy", %{user: user, widget: widget} do
      opts = as_token(user, ["read"])

      assert {:error, %Forbidden{}} = Widget.create("gear", opts)
      assert {:error, %Forbidden{}} = Widget.rename(widget, "gear", opts)
      assert {:error, %Forbidden{}} = Widget.remove(widget, opts)
      assert widget_names(user) == ["sprocket"]
    end

    test "a read-only token can still read and run generic actions", %{user: user} do
      opts = as_token(user, ["read"])

      assert {:ok, [%Widget{name: "sprocket"}]} = Widget.list(opts)
      assert {:ok, 0} = Widget.count_widgets(opts)
    end

    test "a write a generic action runs with its context passed on is still refused", %{
      user: user
    } do
      assert {:error, %Forbidden{}} = Widget.plant("gear", as_token(user, ["read"]))

      assert {:ok, %Widget{name: "gear"}} =
               Widget.plant("gear", as_token(user, ["read", "write"]))
    end

    test "it is the shared copy of the context that reaches nested actions", %{user: user} do
      top_level_only = [
        actor: user,
        context: %{api_gatehouse: %{scopes: ["read"], client_id: "client"}}
      ]

      assert {:ok, %Widget{name: "gear"}} = Widget.plant("gear", top_level_only)
    end

    test "a token granted write is not restricted", %{user: user, widget: widget} do
      opts = as_token(user, ["read", "write"])

      assert {:ok, %Widget{}} = Widget.create("gear", opts)
      assert {:ok, %Widget{name: "cog"}} = Widget.rename(widget, "cog", opts)
    end

    test "a request that did not come in on an API token is not restricted", %{user: user} do
      assert {:ok, %Widget{}} = Widget.create("gear", actor: user)
      assert {:ok, %Widget{}} = Widget.create("cog", actor: user, context: %{api?: true})
    end
  end

  describe "on a resource" do
    test "a read-only token cannot create, a write token can, and reads are open", %{user: user} do
      assert {:error, %Forbidden{}} = Gadget.create("lever", as_token(user, ["read"]))
      assert {:ok, %Gadget{}} = Gadget.create("lever", as_token(user, ["write"]))
      assert {:ok, [%Gadget{name: "lever"}]} = Gadget.list(as_token(user, ["read"]))
    end

    test "the resource's own policies still decide", %{user: user} do
      assert {:error, %Forbidden{}} =
               Gadget.create("lever", Keyword.delete(as_token(user, ["write"]), :actor))
    end
  end

  test "over the API, the bearer token's scopes decide whether a write runs" do
    user = User.admin()
    %{tokens: read_only} = Flow.connect(user)
    %{tokens: read_write} = Flow.connect(user, %{scopes: ["read", "write"]})

    assert Flow.api(:post, "/widgets", read_only["access_token"], %{"name" => "gear"}).status ==
             403

    assert Flow.api(:post, "/widgets", read_write["access_token"], %{"name" => "cog"}).status ==
             201

    assert Flow.api(:get, "/widgets", read_only["access_token"]).status == 200
  end

  test "the check only matches a scope list without write" do
    context = fn gatehouse -> %{subject: %{context: %{api_gatehouse: gatehouse}}} end

    assert TokenLacksWriteScope.match?(nil, context.(%{scopes: ["read"]}), [])
    assert TokenLacksWriteScope.match?(nil, context.(%{scopes: []}), [])
    refute TokenLacksWriteScope.match?(nil, context.(%{scopes: ["read", "write"]}), [])
    refute TokenLacksWriteScope.match?(nil, context.(%{scopes: "read"}), [])
    refute TokenLacksWriteScope.match?(nil, context.(%{}), [])
    refute TokenLacksWriteScope.match?(nil, %{subject: %{context: %{}}}, [])
  end
end
