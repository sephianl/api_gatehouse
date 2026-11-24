defmodule ApiGatehouse.Test.Plain do
  @moduledoc """
  A second host shape: a client resource without multitenancy, whose own
  `action_type(:read)` policy would also cover the library's lookups, so it
  starts its policies with the server actor bypass, as the README says such a
  host must.
  """
  use Ash.Domain

  resources do
    resource ApiGatehouse.Test.PlainClient
    resource ApiGatehouse.Test.PlainAccessToken
  end
end

defmodule ApiGatehouse.Test.PlainClient do
  @moduledoc "A client resource without multitenancy and with a broad host policy behind the bypass."
  use Ash.Resource,
    domain: ApiGatehouse.Test.Plain,
    data_layer: Ash.DataLayer.Ets,
    fragments: [ApiGatehouse.OAuth.ClientFragment]

  api_gatehouse do
    server ApiGatehouse.Test.PlainServer
  end

  ets do
    private? true
  end

  policies do
    bypass ApiGatehouse.OAuth.Checks.ServerActor do
      authorize_if always()
    end

    policy action_type(:create) do
      authorize_if actor_attribute_equals(:role, :admin)
    end

    policy action_type([:read, :update]) do
      authorize_if expr(company_id == ^actor(:company_id))
    end
  end

  # Ash.DataLayer.Verifiers.RequirePreCheckWith: ETS cannot enforce identities; Postgres hosts do.
  @spec testing_identities() :: true
  def testing_identities, do: true
end

defmodule ApiGatehouse.Test.PlainAccessToken do
  @moduledoc "The fragment's access token resource for the plain host, with nothing added."
  use Ash.Resource,
    domain: ApiGatehouse.Test.Plain,
    data_layer: Ash.DataLayer.Ets,
    fragments: [ApiGatehouse.OAuth.AccessTokenFragment]

  ets do
    private? true
  end

  # Ash.DataLayer.Verifiers.RequirePreCheckWith: ETS cannot enforce identities; Postgres hosts do.
  @spec testing_identities() :: true
  def testing_identities, do: true
end

defmodule ApiGatehouse.Test.PlainServer do
  @moduledoc "The plain host's server."
  @behaviour ApiGatehouse.Server

  @impl true
  def client_resource, do: ApiGatehouse.Test.PlainClient
  @impl true
  def access_token_resource, do: ApiGatehouse.Test.PlainAccessToken
  @impl true
  defdelegate load_owner(owner_id, company_id), to: ApiGatehouse.Test.User, as: :load
end
