defmodule ApiGatehouse.Test.Server do
  @moduledoc """
  The host's `ApiGatehouse.Server`, implementing the optional `trusted_proxies/0`
  and `bearer_cache_ttl/0`, so every API request in the suite runs through the
  bearer cache, and leaving the rest to their defaults.
  """
  @behaviour ApiGatehouse.Server

  alias ApiGatehouse.Test.User

  @impl true
  def client_resource, do: ApiGatehouse.Test.Client

  @impl true
  def access_token_resource, do: ApiGatehouse.Test.AccessToken

  @impl true
  def load_owner(owner_id, company_id), do: User.load(owner_id, company_id)

  @impl true
  def trusted_proxies, do: ["35.191.0.0/16"]

  @impl true
  def bearer_cache_ttl, do: 60
end

defmodule ApiGatehouse.Test.MinimalServer do
  @moduledoc "A host server implementing only the required callbacks, so every default applies."
  @behaviour ApiGatehouse.Server

  alias ApiGatehouse.Test.Server

  @impl true
  defdelegate client_resource, to: Server
  @impl true
  defdelegate access_token_resource, to: Server
  @impl true
  defdelegate load_owner(owner_id, company_id), to: Server
end

defmodule ApiGatehouse.Test.ConfiguredServer do
  @moduledoc """
  A host server answering every optional callback with a non-default value:
  ten-minute access tokens, refresh tokens that expire after a minute unused,
  read as the only scope, and two minutes of bearer caching.
  """
  @behaviour ApiGatehouse.Server

  alias ApiGatehouse.Test.Server

  @impl true
  defdelegate client_resource, to: Server
  @impl true
  defdelegate access_token_resource, to: Server
  @impl true
  defdelegate load_owner(owner_id, company_id), to: Server
  @impl true
  def access_token_ttl, do: 600
  @impl true
  def refresh_idle_ttl, do: 60
  @impl true
  def issue_refresh_token?, do: true
  @impl true
  def scopes, do: ["read"]
  @impl true
  def trusted_proxies, do: ["130.211.0.0/22"]
  @impl true
  def bearer_cache_ttl, do: 120
end

defmodule ApiGatehouse.Test.NoRefreshServer do
  @moduledoc "A host server that issues no refresh tokens."
  @behaviour ApiGatehouse.Server

  alias ApiGatehouse.Test.Server

  @impl true
  defdelegate client_resource, to: Server
  @impl true
  defdelegate access_token_resource, to: Server
  @impl true
  defdelegate load_owner(owner_id, company_id), to: Server
  @impl true
  def issue_refresh_token?, do: false
end

defmodule ApiGatehouse.Test.LazyServer do
  @moduledoc "A host server that only one test touches, so that test can unload it first."
  @behaviour ApiGatehouse.Server

  alias ApiGatehouse.Test.Server

  @impl true
  defdelegate client_resource, to: Server
  @impl true
  defdelegate access_token_resource, to: Server
  @impl true
  defdelegate load_owner(owner_id, company_id), to: Server
  @impl true
  def refresh_idle_ttl, do: 42
end

defmodule ApiGatehouse.Test.FailingTokens do
  @moduledoc """
  The host's access token resource, except that `revoke_family/4` fails with a
  validation error, as a data layer refusing the write would, and `issue/2`
  fails too.
  """

  alias ApiGatehouse.Test.AccessToken
  alias Ash.Error.Changes.InvalidAttribute

  @spec get_by_refresh_token(String.t(), keyword()) :: {:ok, struct()} | {:error, term()}
  defdelegate get_by_refresh_token(refresh_token, opts), to: AccessToken

  @spec revoke_family(String.t(), String.t(), String.t(), keyword()) :: {:error, term()}
  def revoke_family(_client_id, _owner_id, _company_id, _opts), do: refused(:revoked_at)

  @spec issue(map(), keyword()) :: {:error, term()}
  def issue(_attrs, _opts), do: refused(:token_hash)

  defp refused(field),
    do: {:error, Ash.Error.to_error_class(InvalidAttribute.exception(field: field, message: "write refused"))}
end

defmodule ApiGatehouse.Test.RacingTokens do
  @moduledoc """
  The host's access token resource, except that `rotate/2` first rotates the row
  itself, so the token endpoint then rotates a row someone else rotated after
  it was read, as a concurrent refresh would on Postgres.
  """

  alias ApiGatehouse.Test.AccessToken

  @spec get_by_refresh_token(String.t(), keyword()) :: {:ok, struct()} | {:error, term()}
  defdelegate get_by_refresh_token(refresh_token, opts), to: AccessToken

  @spec issue(map(), keyword()) :: {:ok, struct()} | {:error, term()}
  defdelegate issue(attrs, opts), to: AccessToken

  @spec rotate(struct(), keyword()) :: {:ok, struct()} | {:error, term()}
  def rotate(row, opts) do
    {:ok, _first} = AccessToken.rotate(row, opts)

    AccessToken.rotate(row, opts)
  end
end

defmodule ApiGatehouse.Test.FailingServer do
  @moduledoc "A host server whose access token rows can be read but neither issued nor revoked."
  @behaviour ApiGatehouse.Server

  alias ApiGatehouse.Test.Server

  @impl true
  defdelegate client_resource, to: Server
  @impl true
  def access_token_resource, do: ApiGatehouse.Test.FailingTokens
  @impl true
  defdelegate load_owner(owner_id, company_id), to: Server
end

defmodule ApiGatehouse.Test.RacingServer do
  @moduledoc "A host server whose refresh rotation always loses the race."
  @behaviour ApiGatehouse.Server

  alias ApiGatehouse.Test.Server

  @impl true
  defdelegate client_resource, to: Server
  @impl true
  def access_token_resource, do: ApiGatehouse.Test.RacingTokens
  @impl true
  defdelegate load_owner(owner_id, company_id), to: Server
end

defmodule ApiGatehouse.Test.DemotableServer do
  @moduledoc """
  The test server, except that an owner whose id the calling process listed
  under `:api_gatehouse_demoted` no longer loads, as after a demotion: the
  owner check a cached token still has to pass.
  """
  @behaviour ApiGatehouse.Server

  alias ApiGatehouse.Test.Server

  @impl true
  defdelegate client_resource, to: Server
  @impl true
  defdelegate access_token_resource, to: Server
  @impl true
  defdelegate bearer_cache_ttl, to: Server

  @impl true
  def load_owner(owner_id, company_id) do
    if owner_id in Process.get(:api_gatehouse_demoted, []),
      do: {:error, :demoted},
      else: Server.load_owner(owner_id, company_id)
  end

  @doc "Demotes `owner_id` for the rest of the calling process."
  @spec demote(String.t()) :: term()
  def demote(owner_id), do: Process.put(:api_gatehouse_demoted, [owner_id | Process.get(:api_gatehouse_demoted, [])])
end

defmodule ApiGatehouse.Test.OverlongCacheServer do
  @moduledoc "A host server asking to cache bearer rows for longer than the library allows."
  @behaviour ApiGatehouse.Server

  alias ApiGatehouse.Test.Server

  @impl true
  defdelegate client_resource, to: Server
  @impl true
  defdelegate access_token_resource, to: Server
  @impl true
  defdelegate load_owner(owner_id, company_id), to: Server
  @impl true
  def bearer_cache_ttl, do: 3600
end
