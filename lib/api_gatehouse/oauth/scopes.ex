defmodule ApiGatehouse.OAuth.Scopes do
  @moduledoc """
  Decides the scopes a token is granted.

  A token is granted the scopes the client asked for in its `scope` parameter
  (RFC 6749 §3.3, space-delimited), which must all be within what it may have:
  the client's own scopes and the server's (and, on a refresh, the scopes of the
  token being refreshed, §6). Without a `scope` parameter it gets everything it
  may have. Unlike an authorization-code server, an unknown scope is refused
  with `invalid_scope` rather than dropped: a machine client asking for more than
  it was configured with is a configuration error worth surfacing.
  """

  @doc "The scopes in every one of `lists`, in the order of the first."
  @spec allowed([[String.t()]]) :: [String.t()]
  def allowed([first | rest]), do: Enum.filter(first, fn scope -> Enum.all?(rest, &(scope in &1)) end)

  @doc """
  The scopes to grant for a `scope` parameter, given what the client may have.
  `:invalid_request` for a parameter that is not a string, `:invalid_scope` for
  one naming a scope outside `allowed` or when nothing at all can be granted.
  """
  @spec grant(term(), [String.t()]) ::
          {:ok, [String.t()]} | {:error, :invalid_request | :invalid_scope}
  def grant(_requested, []), do: {:error, :invalid_scope}
  def grant(nil, allowed), do: {:ok, allowed}

  def grant(requested, allowed) when is_binary(requested) do
    case requested |> String.split(" ", trim: true) |> Enum.uniq() do
      [] ->
        {:ok, allowed}

      scopes ->
        if Enum.all?(scopes, &(&1 in allowed)), do: {:ok, scopes}, else: {:error, :invalid_scope}
    end
  end

  def grant(_requested, _allowed), do: {:error, :invalid_request}
end
