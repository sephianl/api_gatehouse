defmodule ApiGatehouse.Test.WidgetApi do
  @moduledoc """
  Stands in for the host's API behind `ApiGatehouse.Plug.Bearer` (an
  `AshJsonApi` router or `Absinthe.Plug`): runs Ash actions with the actor,
  tenant and context the bearer plug put on the connection.

    * `GET /widgets` lists widget names.
    * `POST /widgets` creates a widget named by the `name` parameter.
    * `GET /whoami` reports the actor id, tenant and `api_gatehouse` context.
  """
  use Plug.Router

  alias ApiGatehouse.Plug.Json
  alias ApiGatehouse.Test.Widget
  alias Ash.PlugHelpers

  plug :match
  plug :dispatch

  get "/widgets" do
    {:ok, widgets} = Widget.list(ash_opts(conn))

    Json.send_json(conn, 200, %{names: widgets |> Enum.map(& &1.name) |> Enum.sort()})
  end

  post "/widgets" do
    case Widget.create(conn.params["name"], ash_opts(conn)) do
      {:ok, widget} -> Json.send_json(conn, 201, %{name: widget.name})
      {:error, %Ash.Error.Forbidden{}} -> Json.send_json(conn, 403, %{error: "forbidden"})
    end
  end

  get "/whoami" do
    Json.send_json(conn, 200, %{
      actor: PlugHelpers.get_actor(conn).id,
      tenant: PlugHelpers.get_tenant(conn),
      api_gatehouse: PlugHelpers.get_context(conn).api_gatehouse
    })
  end

  match _ do
    send_resp(conn, 404, "")
  end

  defp ash_opts(conn) do
    [
      actor: PlugHelpers.get_actor(conn),
      tenant: PlugHelpers.get_tenant(conn),
      context: PlugHelpers.get_context(conn)
    ]
  end
end
