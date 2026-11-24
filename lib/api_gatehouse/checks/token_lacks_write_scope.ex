defmodule ApiGatehouse.Checks.TokenLacksWriteScope do
  @moduledoc """
  True when the request came in on an API access token that was not granted the
  `write` scope.

  `ApiGatehouse.Plug.Bearer` puts the token's scopes into the Ash context as
  `%{api_gatehouse: %{scopes: scopes}}`; a request without that key did not come
  in on an API token and never matches.
  """
  use Ash.Policy.SimpleCheck

  @write "write"

  @impl true
  @spec describe(keyword()) :: String.t()
  def describe(_options), do: "request uses an API token without the #{@write} scope"

  @impl true
  @spec match?(term(), map(), keyword()) :: boolean()
  def match?(_actor, %{subject: %{context: %{api_gatehouse: %{scopes: scopes}}}}, _options) when is_list(scopes),
    do: @write not in scopes

  def match?(_actor, _context, _options), do: false
end
