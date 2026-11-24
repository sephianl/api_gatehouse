defmodule ApiGatehouse.OAuth.Lookup do
  @moduledoc """
  Finds the OAuth rows a request presents a value for, in the host's resources
  and as `ApiGatehouse.OAuth.ServerActor`.

  Each lookup answers `{:ok, row}` or `:error`, whatever the reason the row was
  not found — including a value that is not a string at all — so the caller
  decides which OAuth error a miss becomes.
  """

  alias ApiGatehouse.OAuth.ServerActor

  @doc "The live (not deleted) client presenting `client_id`."
  @spec fetch_client(module(), term()) :: {:ok, struct()} | :error
  def fetch_client(server, client_id) when is_binary(client_id),
    do: found(server.client_resource().get_by_client_id(client_id, actor: ServerActor.new()))

  def fetch_client(_server, _client_id), do: :error

  @doc "The live (not deleted) client with row id `id`."
  @spec fetch_client_by_id(module(), term()) :: {:ok, struct()} | :error
  def fetch_client_by_id(server, id) when is_binary(id),
    do: found(server.client_resource().get_by_id(id, actor: ServerActor.new()))

  def fetch_client_by_id(_server, _id), do: :error

  @doc "The live token row for a raw access token."
  @spec fetch_by_access_token(module(), term()) :: {:ok, struct()} | :error
  def fetch_by_access_token(server, token) when is_binary(token),
    do: found(server.access_token_resource().get_by_access_token(token, actor: ServerActor.new()))

  def fetch_by_access_token(_server, _token), do: :error

  @doc "The token row for a raw refresh token, whatever its state."
  @spec fetch_by_refresh_token(module(), term()) :: {:ok, struct()} | :error
  def fetch_by_refresh_token(server, token) when is_binary(token),
    do: found(server.access_token_resource().get_by_refresh_token(token, actor: ServerActor.new()))

  def fetch_by_refresh_token(_server, _token), do: :error

  defp found({:ok, %{} = row}), do: {:ok, row}
  defp found(_not_found), do: :error
end
