defmodule ApiGatehouse.Resource.Verifiers.RequireServer do
  @moduledoc """
  Refuses to compile a client resource that names no server in its
  `api_gatehouse` section: creating or deleting a client would otherwise fail
  only at runtime.
  """
  use Spark.Dsl.Verifier

  alias Spark.Dsl.Verifier
  alias Spark.Error.DslError

  @impl true
  @spec verify(map()) :: :ok | {:error, DslError.t()}
  def verify(dsl) do
    if Verifier.get_option(dsl, [:api_gatehouse], :server) do
      :ok
    else
      {:error,
       DslError.exception(
         module: Verifier.get_persisted(dsl, :module),
         path: [:api_gatehouse, :server],
         message: """
         a client resource must name its server:

             api_gatehouse do
               server MyAppWeb.ApiServer
             end
         """
       )}
    end
  end
end
