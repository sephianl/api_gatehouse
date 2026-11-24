defmodule ApiGatehouse.Resource do
  @moduledoc """
  The `api_gatehouse` section of a host's client resource, brought in by
  `ApiGatehouse.OAuth.ClientFragment`. It names the host's
  `ApiGatehouse.Server`, which the client actions need: creating a client checks
  its scopes against `c:ApiGatehouse.Server.scopes/0`, and soft-deleting one
  revokes its tokens in `c:ApiGatehouse.Server.access_token_resource/0`.

      api_gatehouse do
        server MyAppWeb.ApiServer
      end

  The server is recorded without a compile-time dependency on it, so the
  resource and the server module can refer to each other. A client resource
  without it is a compile-time warning
  (`ApiGatehouse.Resource.Verifiers.RequireServer`).
  """

  use Spark.Dsl.Extension,
    sections: [
      %Spark.Dsl.Section{
        name: :api_gatehouse,
        describe: "Names the host's `ApiGatehouse.Server` for the client actions.",
        examples: [
          """
          api_gatehouse do
            server MyAppWeb.ApiServer
          end
          """
        ],
        no_depend_modules: [:server],
        schema: [
          server: [
            type: :atom,
            doc: "The host module implementing `ApiGatehouse.Server`."
          ]
        ]
      }
    ],
    verifiers: [ApiGatehouse.Resource.Verifiers.RequireServer]
end
