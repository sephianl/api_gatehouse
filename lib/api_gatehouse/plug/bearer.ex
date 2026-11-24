defmodule ApiGatehouse.Plug.Bearer do
  @moduledoc """
  Authenticates an API request by its `Authorization: Bearer` access token.

      plug ApiGatehouse.Plug.Bearer

  after `ApiGatehouse.Plug.Server` in the pipeline, or with its own
  `server: MyAppWeb.ApiServer`. With neither it raises rather than let the
  request through.

  A token authenticates while it is neither revoked nor expired, its client is
  not deleted (and still has the owner and company the token was issued for),
  and the owner loads through `c:ApiGatehouse.Server.load_owner/2` as a non-nil
  actor whose `:company_id`, when it has one, is the token's. Nothing is
  cached: every request reads the token and client rows and loads the owner, so
  revocation, deletion and demotion take effect on the next request.

  The request then carries that actor (`Ash.PlugHelpers.set_actor/2`), the
  token's company as tenant (`Ash.PlugHelpers.set_tenant/2`), and an Ash
  context merged into whatever an earlier plug set:

      %{api_gatehouse: %{scopes: ["read"], client_id: "the public client id"}}

  also under `:shared`, so Ash passes it on to the actions nested in the one the
  request runs. A key of that name set earlier is replaced, never merged into,
  so nothing upstream can widen a token's scopes. `ApiGatehouse.ReadOnlyScopePolicy`
  reads it. The token row is assigned as `:api_gatehouse_token` and the client
  row as `:api_gatehouse_client`, for host plugs. The `Bearer` scheme is matched
  case-insensitively (RFC 7235).

  A rejection is a 401 `{"error":"invalid_token"}` with the RFC 6750 challenge
  `WWW-Authenticate: Bearer error="invalid_token"`, or a bare
  `WWW-Authenticate: Bearer` when no bearer token was presented at all (§3.1).
  """
  @behaviour Plug

  import Plug.Conn

  alias ApiGatehouse.OAuth.Lookup
  alias ApiGatehouse.Plug.Json
  alias ApiGatehouse.Plug.Options
  alias ApiGatehouse.Server.Callbacks
  alias Ash.PlugHelpers

  @impl Plug
  @spec init(keyword()) :: map()
  def init(opts), do: Options.validate(__MODULE__, opts)

  @impl Plug
  @spec call(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def call(conn, opts) do
    case authenticate(conn, Options.server(conn, __MODULE__, opts)) do
      {:ok, authenticated} -> authenticated
      {:error, :missing} -> unauthorized(conn, ~s(Bearer))
      {:error, :invalid_token} -> unauthorized(conn, ~s(Bearer error="invalid_token"))
    end
  end

  @doc """
  Authenticates `conn` against `server` exactly as `call/2` does, but leaves the
  response to the caller: `{:ok, conn}` carrying the actor, tenant, context and
  assigns; `{:error, :missing}` when no bearer token was presented; or
  `{:error, :invalid_token}`. Nothing is sent and nothing halted.

  For a host whose API also accepts other credentials, which has to decide per
  request which authenticator applies.
  """
  @spec authenticate(Plug.Conn.t(), module()) ::
          {:ok, Plug.Conn.t()} | {:error, :missing | :invalid_token}
  def authenticate(conn, server) do
    with {:ok, presented} <- bearer_token(conn),
         {:ok, token} <- Lookup.fetch_by_access_token(server, presented),
         :ok <- usable(token),
         {:ok, client} <- Lookup.fetch_client_by_id(server, token.client_id),
         :ok <- issued_for(token, client),
         {:ok, actor} <- Callbacks.load_owner(server, token.owner_id, token.company_id) do
      {:ok, authenticated(conn, token, client, actor)}
    else
      :missing -> {:error, :missing}
      _rejected -> {:error, :invalid_token}
    end
  end

  defp bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      [header | _rest] -> parse_bearer(header)
      [] -> :missing
    end
  end

  defp parse_bearer(header) do
    with [scheme, credential] <- String.split(header, " ", parts: 2),
         "bearer" <- String.downcase(scheme),
         token when token != "" <- String.trim(credential) do
      {:ok, token}
    else
      _not_bearer -> :missing
    end
  end

  defp usable(%{revoked_at: nil, expires_at: expires_at}) do
    if DateTime.after?(expires_at, DateTime.utc_now()), do: :ok, else: :error
  end

  defp usable(_token), do: :error

  defp issued_for(%{owner_id: owner_id, company_id: company_id}, %{owner_id: owner_id, company_id: company_id}), do: :ok

  defp issued_for(_token, _client), do: :error

  defp authenticated(conn, token, client, actor) do
    gatehouse = %{scopes: token.scopes, client_id: client.client_id}

    conn
    |> PlugHelpers.set_actor(actor)
    |> PlugHelpers.set_tenant(token.company_id)
    |> PlugHelpers.update_context(&with_gatehouse(&1, gatehouse))
    |> assign(:api_gatehouse_token, token)
    |> assign(:api_gatehouse_client, client)
  end

  defp with_gatehouse(context, gatehouse) do
    context = context || %{}
    shared = Map.get(context, :shared) || %{}

    context
    |> Map.put(:api_gatehouse, gatehouse)
    |> Map.put(:shared, Map.put(shared, :api_gatehouse, gatehouse))
  end

  defp unauthorized(conn, challenge) do
    conn
    |> put_resp_header("www-authenticate", challenge)
    |> Json.send_json(401, %{error: "invalid_token"})
    |> halt()
  end
end
