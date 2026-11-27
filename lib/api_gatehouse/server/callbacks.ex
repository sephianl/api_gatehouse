defmodule ApiGatehouse.Server.Callbacks do
  @moduledoc """
  Reads a host's `ApiGatehouse.Server`, applying the defaults for the optional
  callbacks it leaves out.

  An optional callback counts as implemented only once the module is loaded:
  `function_exported?/3` is false for a module nothing has loaded yet, which in
  dev and test would silently swap a host's answer for the default on the first
  request of a fresh VM.
  """

  alias ApiGatehouse.BearerCache

  @default_access_token_ttl 3600
  @default_refresh_idle_ttl 90 * 24 * 3600
  @default_scopes ["read", "write"]

  @doc "Seconds an access token stays valid."
  @spec access_token_ttl(module()) :: pos_integer()
  def access_token_ttl(server), do: optional(server, :access_token_ttl, @default_access_token_ttl)

  @doc "Seconds a refresh token may sit unused."
  @spec refresh_idle_ttl(module()) :: pos_integer()
  def refresh_idle_ttl(server), do: optional(server, :refresh_idle_ttl, @default_refresh_idle_ttl)

  @doc "Whether refresh tokens are issued and the refresh grant accepted."
  @spec issue_refresh_token?(module()) :: boolean()
  def issue_refresh_token?(server), do: optional(server, :issue_refresh_token?, true)

  @doc "Every scope a token can carry."
  @spec scopes(module()) :: [String.t()]
  def scopes(server), do: optional(server, :scopes, @default_scopes)

  @doc "The proxies trusted to append to `X-Forwarded-For`."
  @spec trusted_proxies(module()) :: [String.t()]
  def trusted_proxies(server), do: optional(server, :trusted_proxies, [])

  @doc "Seconds the bearer plug may keep a token's rows, held between 0 and `ApiGatehouse.BearerCache.max_ttl_seconds/0`."
  @spec bearer_cache_ttl(module()) :: non_neg_integer()
  def bearer_cache_ttl(server),
    do: server |> optional(:bearer_cache_ttl, 0) |> max(0) |> min(BearerCache.max_ttl_seconds())

  @doc """
  Loads a client's owner and checks it belongs to the client's company.

  `{:ok, nil}`, any answer other than `{:ok, actor}`, and an actor whose
  `:company_id` is not `company_id` are refused here, so a host loader that
  forgot its tenant cannot authenticate across companies.
  """
  @spec load_owner(module(), String.t(), String.t()) :: {:ok, term()} | :error
  def load_owner(server, owner_id, company_id) do
    case server.load_owner(owner_id, company_id) do
      {:ok, actor} -> owned_by(actor, company_id)
      _not_loaded -> :error
    end
  end

  defp owned_by(nil, _company_id), do: :error
  defp owned_by(%{company_id: company_id} = actor, company_id), do: {:ok, actor}
  defp owned_by(%{company_id: _other_company}, _company_id), do: :error
  defp owned_by(actor, _company_id), do: {:ok, actor}

  defp optional(server, name, default) do
    if Code.ensure_loaded?(server) and function_exported?(server, name, 0),
      do: apply(server, name, []),
      else: default
  end
end
