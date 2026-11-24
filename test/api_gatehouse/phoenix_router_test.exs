defmodule ApiGatehouse.PhoenixRouterTest do
  @moduledoc """
  The documented router wiring, compiled by Phoenix rather than `Plug.Router`:
  `ApiGatehouse.Test.PhoenixRouter` copies README §4, every flow test goes
  through it, and README §4 still matches it statement for statement. A wiring
  that only works in `Plug.Router` (such as a two-argument `post`) fails here
  instead of in a host.
  """
  use ExUnit.Case, async: true

  import Plug.Conn

  alias ApiGatehouse.Test.Flow
  alias ApiGatehouse.Test.User

  @router_source "test/support/phoenix_router.ex"
  @doc_names [
    {"MyAppWeb.ApiServer", "ApiGatehouse.Test.Server"},
    {"MyAppWeb.JsonApiRouter", "ApiGatehouse.Test.WidgetApi"}
  ]
  @pipelines [:api_oauth, :api_oauth_token, :api_oauth_revoke, :api]

  test "the documented routes answer" do
    %{client_id: client_id, secret: secret} = Flow.create_client(User.admin())

    assert Flow.post_form("/api/oauth/token", %{"grant_type" => "password"}).status == 400

    assert %{"access_token" => access_token} =
             client_id |> Flow.token_basic(secret) |> Flow.json()

    assert Flow.api(:get, "/whoami", access_token).status == 200
    assert Flow.revoke(client_id, secret, %{"token" => access_token}).status == 200

    unauthenticated = Flow.api(:get, "/widgets", nil)
    assert unauthenticated.status == 401
    assert get_resp_header(unauthenticated, "www-authenticate") == ["Bearer"]
  end

  test "README §4 wires the library exactly as the Phoenix test router does" do
    [_before, section] = "README.md" |> File.read!() |> String.split("### 4. Router", parts: 2)
    [_prose, code] = String.split(section, "```elixir\n", parts: 2)
    [code, _rest] = String.split(code, "```", parts: 2)

    assert doc_wiring(code) == router_wiring()
  end

  defp doc_wiring(code) do
    @doc_names
    |> Enum.reduce(code, fn {doc_name, test_name}, acc ->
      String.replace(acc, doc_name, test_name)
    end)
    |> Code.string_to_quoted!()
    |> library_wiring(%{})
  end

  defp router_wiring do
    {:defmodule, _meta, [_name, [do: body]]} =
      @router_source |> File.read!() |> Code.string_to_quoted!() |> statements() |> hd()

    aliases =
      for {:alias, _meta, [{:__aliases__, _alias_meta, parts}]} <- statements(body),
          into: %{},
          do: {List.last(parts), parts}

    library_wiring(body, aliases)
  end

  defp library_wiring(ast, aliases) do
    ast
    |> statements()
    |> Enum.filter(&library_wiring?/1)
    |> Enum.map(&normalize(&1, aliases))
  end

  defp normalize(statement, aliases) do
    statement
    |> Macro.prewalk(fn
      {:__aliases__, _meta, [single]} when is_map_key(aliases, single) ->
        {:__aliases__, [], aliases[single]}

      node ->
        Macro.update_meta(node, fn _meta -> [] end)
    end)
    |> Macro.to_string()
  end

  defp statements({:__block__, _meta, statements}), do: statements
  defp statements(statement), do: [statement]

  defp library_wiring?({:pipeline, _meta, [name, _block]}), do: name in @pipelines
  defp library_wiring?({:scope, _meta, [_path, [do: _block]]}), do: true
  defp library_wiring?(_statement), do: false
end
