defmodule ApiGatehouse.Test.PhoenixRouter do
  @moduledoc """
  The README's router, compiled by Phoenix's own route and pipeline macros, with
  `ApiGatehouse.Test.Server` for `MyAppWeb.ApiServer` and
  `ApiGatehouse.Test.WidgetApi` for `MyAppWeb.JsonApiRouter`.

  `ApiGatehouse.PhoenixRouterTest` checks that the README wires the library
  exactly as this module does, so a change to a plug's options that breaks this
  router breaks the documented wiring too. Every flow test goes through it.
  """
  use Phoenix.Router, helpers: false

  import Phoenix.Controller
  import Plug.Conn

  alias ApiGatehouse.Plug.RateLimit
  alias ApiGatehouse.Plug.Server

  pipeline :api_oauth do
    plug Server, server: ApiGatehouse.Test.Server
    plug :accepts, ["json"]
  end

  pipeline :api_oauth_token do
    plug RateLimit, bucket: "api_oauth_token", limit: 20
  end

  pipeline :api_oauth_revoke do
    plug RateLimit, bucket: "api_oauth_revoke", limit: 30
  end

  pipeline :api do
    plug Server, server: ApiGatehouse.Test.Server
    plug :accepts, ["json"]
    plug ApiGatehouse.Plug.Bearer
  end

  scope "/api/oauth" do
    pipe_through [:api_oauth, :api_oauth_token]

    post "/token", ApiGatehouse.Plug.Token, []
  end

  scope "/api/oauth" do
    pipe_through [:api_oauth, :api_oauth_revoke]

    post "/revoke", ApiGatehouse.Plug.Revocation, []
  end

  scope "/api" do
    pipe_through :api

    forward "/json", ApiGatehouse.Test.WidgetApi
  end
end

defmodule ApiGatehouse.Test.Endpoint do
  @moduledoc "The part of a host endpoint the router relies on: body parsing in front of it."
  use Plug.Builder

  plug Plug.Parsers, parsers: [:urlencoded, :json], pass: ["*/*"], json_decoder: Jason
  plug ApiGatehouse.Test.PhoenixRouter
end
