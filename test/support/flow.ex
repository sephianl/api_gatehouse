defmodule ApiGatehouse.Test.Flow do
  @moduledoc """
  Drives `ApiGatehouse.Test.Endpoint` the way an API integration does: create a
  client (as the host's admin screen would), get a token with its credentials,
  call the API, refresh and revoke.
  """

  import Plug.Conn
  import Plug.Test

  alias ApiGatehouse.OAuth.OpaqueToken
  alias ApiGatehouse.OAuth.ServerActor
  alias ApiGatehouse.Test.AccessToken
  alias ApiGatehouse.Test.Client
  alias ApiGatehouse.Test.Endpoint

  require Ash.Query

  @endpoint_opts Endpoint.init([])

  @doc "Creates a client owned by `user` in `user`'s company, returning it with its secret."
  @spec create_client(struct(), map()) :: %{
          client: struct(),
          client_id: String.t(),
          secret: String.t()
        }
  def create_client(user, attrs \\ %{}) do
    {:ok, client} =
      %{name: "ERP sync", owner_id: user.id, company_id: user.company_id}
      |> Map.merge(attrs)
      |> Client.create(actor: user, tenant: user.company_id)

    %{client: client, client_id: client.client_id, secret: client.__metadata__.client_secret}
  end

  @doc "The `Authorization` header value for HTTP Basic client authentication."
  @spec basic(String.t(), String.t()) :: String.t()
  def basic(client_id, secret) do
    "Basic " <>
      Base.encode64(URI.encode_www_form(client_id) <> ":" <> URI.encode_www_form(secret))
  end

  @doc "POSTs a form to `path` through the endpoint, with `headers`."
  @spec post_form(String.t(), map(), [{String.t(), String.t()}]) :: Plug.Conn.t()
  def post_form(path, params, headers \\ []) do
    :post
    |> conn(path, URI.encode_query(params))
    |> put_req_header("content-type", "application/x-www-form-urlencoded")
    |> with_headers(headers)
    |> request()
  end

  @doc "POSTs a JSON body to `path` through the endpoint, with `headers`."
  @spec post_json(String.t(), map(), [{String.t(), String.t()}]) :: Plug.Conn.t()
  def post_json(path, body, headers \\ []) do
    :post
    |> conn(path, Jason.encode!(body))
    |> put_req_header("content-type", "application/json")
    |> with_headers(headers)
    |> request()
  end

  @doc "A token request authenticated with HTTP Basic."
  @spec token_basic(String.t(), String.t(), map()) :: Plug.Conn.t()
  def token_basic(client_id, secret, params \\ %{"grant_type" => "client_credentials"}) do
    post_form("/api/oauth/token", params, [{"authorization", basic(client_id, secret)}])
  end

  @doc "A token request authenticated with the credentials in the body."
  @spec token_post(String.t(), String.t(), map()) :: Plug.Conn.t()
  def token_post(client_id, secret, params \\ %{"grant_type" => "client_credentials"}) do
    post_form(
      "/api/oauth/token",
      Map.merge(%{"client_id" => client_id, "client_secret" => secret}, params)
    )
  end

  @doc "A refresh, authenticated with HTTP Basic."
  @spec refresh(String.t(), String.t(), String.t(), map()) :: Plug.Conn.t()
  def refresh(client_id, secret, refresh_token, params \\ %{}) do
    token_basic(
      client_id,
      secret,
      Map.merge(%{"grant_type" => "refresh_token", "refresh_token" => refresh_token}, params)
    )
  end

  @doc "A revocation, authenticated with HTTP Basic."
  @spec revoke(String.t(), String.t(), map()) :: Plug.Conn.t()
  def revoke(client_id, secret, params) do
    post_form("/api/oauth/revoke", params, [{"authorization", basic(client_id, secret)}])
  end

  @doc "Creates a client for `user` and gets a token with it, returning both."
  @spec connect(struct(), map()) :: map()
  def connect(user, attrs \\ %{}) do
    created = create_client(user, attrs)
    tokens = created.client_id |> token_basic(created.secret) |> json()

    Map.put(created, :tokens, tokens)
  end

  @doc "A request to the API behind the bearer plug, with `token` if given."
  @spec api(atom(), String.t(), String.t() | nil, map()) :: Plug.Conn.t()
  def api(method, path, token, params \\ %{}) do
    method
    |> conn("/api/json" <> path, params)
    |> with_token(token)
    |> request()
  end

  @doc "Whether `access_token` still authenticates an API request."
  @spec authenticates?(String.t()) :: boolean()
  def authenticates?(access_token), do: api(:get, "/whoami", access_token).status == 200

  @doc "The decoded JSON body of a response."
  @spec json(Plug.Conn.t()) :: term()
  def json(conn), do: Jason.decode!(conn.resp_body)

  @doc "The token row a raw refresh token belongs to, whatever its state."
  @spec row_for_refresh(String.t()) :: struct()
  def row_for_refresh(refresh_token) do
    {:ok, row} = AccessToken.get_by_refresh_token(refresh_token, actor: ServerActor.new())
    row
  end

  @doc "The token row a raw access token belongs to, whatever its state."
  @spec row_for_access(String.t()) :: struct()
  def row_for_access(access_token) do
    hash = OpaqueToken.hash(access_token)

    {:ok, [row]} =
      AccessToken
      |> Ash.Query.filter(token_hash == ^hash)
      |> Ash.read(actor: ServerActor.new())

    row
  end

  @doc "Moves `field` of `row` `seconds` into the past."
  @spec backdate(struct(), atom(), integer()) :: struct()
  def backdate(row, field, seconds) do
    {:ok, backdated} = AccessToken.backdate(row, field, seconds, actor: ServerActor.new())
    backdated
  end

  @doc "Issues a token row directly, as the token endpoint would, for `client`."
  @spec issue(struct(), keyword()) :: struct()
  def issue(client, opts \\ []) do
    {:ok, issued} =
      AccessToken.issue(
        %{
          client_id: client.id,
          owner_id: Keyword.get(opts, :owner_id, client.owner_id),
          company_id: Keyword.get(opts, :company_id, client.company_id),
          scopes: Keyword.get(opts, :scopes, client.scopes),
          expires_in: Keyword.get(opts, :expires_in, 3600),
          refresh_expires_in: Keyword.get(opts, :refresh_expires_in, 3600)
        },
        actor: ServerActor.new()
      )

    issued
  end

  @doc "Every token row, as the server actor reads them."
  @spec rows() :: [struct()]
  def rows do
    {:ok, rows} = AccessToken.read(actor: ServerActor.new())
    rows
  end

  @doc "Runs `conn` through the endpoint."
  @spec request(Plug.Conn.t()) :: Plug.Conn.t()
  def request(conn), do: Endpoint.call(conn, @endpoint_opts)

  @doc "Runs `conn` through `plugs`, each initialised from its options, stopping at the first that halts."
  @spec run(Plug.Conn.t(), [{module(), keyword()}]) :: Plug.Conn.t()
  def run(conn, plugs) do
    Enum.reduce_while(plugs, conn, fn {plug, opts}, acc ->
      case plug.call(acc, plug.init(opts)) do
        %Plug.Conn{halted: true} = halted -> {:halt, halted}
        continued -> {:cont, continued}
      end
    end)
  end

  @doc "A token request straight through `ApiGatehouse.Plug.Token` built for `server`."
  @spec token_through(module(), map(), [{String.t(), String.t()}]) :: Plug.Conn.t()
  def token_through(server, params, headers \\ []) do
    :post
    |> conn("/api/oauth/token", URI.encode_query(params))
    |> put_req_header("content-type", "application/x-www-form-urlencoded")
    |> with_headers(headers)
    |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:urlencoded], pass: ["*/*"]))
    |> run([{ApiGatehouse.Plug.Token, server: server}])
  end

  defp with_token(conn, nil), do: conn
  defp with_token(conn, token), do: put_req_header(conn, "authorization", "Bearer #{token}")

  defp with_headers(conn, headers),
    do: Enum.reduce(headers, conn, fn {name, value}, acc -> put_req_header(acc, name, value) end)
end
