defmodule ApiGatehouse.OAuth.Validations.KnownScopes do
  @moduledoc """
  A client's scopes must be a non-empty, duplicate-free subset of
  `c:ApiGatehouse.Server.scopes/0` of the server named in the client resource's
  `api_gatehouse` section.

  The token endpoint grants only scopes in both lists anyway; this refuses a
  client that could never be granted what it was created with, as a field error
  the host's form can show.
  """
  use Ash.Resource.Validation

  alias ApiGatehouse.Resource.Info
  alias ApiGatehouse.Server.Callbacks
  alias Ash.Changeset
  alias Ash.Error.Changes.InvalidAttribute

  @impl true
  @spec validate(Changeset.t(), keyword(), Ash.Resource.Validation.Context.t()) ::
          :ok | {:error, term()}
  def validate(changeset, _opts, _context) do
    known = changeset.resource |> Info.api_gatehouse_server!() |> Callbacks.scopes()

    changeset
    |> Changeset.get_attribute(:scopes)
    |> check(known)
  end

  @impl true
  @spec describe(keyword()) :: keyword()
  def describe(_opts), do: [message: "must be a subset of the server's scopes", vars: []]

  defp check(scopes, known) when is_list(scopes) and scopes != [] do
    cond do
      Enum.uniq(scopes) != scopes -> invalid("must not repeat a scope")
      Enum.all?(scopes, &(&1 in known)) -> :ok
      true -> invalid("must be some of: #{Enum.join(known, ", ")}")
    end
  end

  defp check(_scopes, _known), do: invalid("must name at least one scope")

  defp invalid(message), do: {:error, InvalidAttribute.exception(field: :scopes, message: message)}
end
