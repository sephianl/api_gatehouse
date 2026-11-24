defmodule ApiGatehouse.Test.User do
  @moduledoc """
  The host's user, as the test server loads it.

  A few fixed ids stand for the loader outcomes a host can produce, so tests
  pick an outcome by picking an owner rather than by mutating shared state.
  """

  defstruct [:id, :company_id, role: :admin]

  @type t :: %__MODULE__{id: String.t(), company_id: String.t(), role: atom()}

  @unloadable "00000000-0000-4000-8000-000000000001"
  @loads_as_nil "00000000-0000-4000-8000-000000000002"
  @in_other_company "00000000-0000-4000-8000-000000000003"
  @without_company "00000000-0000-4000-8000-000000000004"

  @doc "An owner the loader refuses, as for a demoted or removed admin."
  @spec unloadable_id() :: String.t()
  def unloadable_id, do: @unloadable

  @doc "An owner the loader answers `{:ok, nil}` for, as a careless `read_one` would."
  @spec loads_as_nil_id() :: String.t()
  def loads_as_nil_id, do: @loads_as_nil

  @doc "An owner the loader returns with a company other than the one asked for."
  @spec in_other_company_id() :: String.t()
  def in_other_company_id, do: @in_other_company

  @doc "An owner the loader returns as an actor without a `:company_id` key."
  @spec without_company_id() :: String.t()
  def without_company_id, do: @without_company

  @doc "A fresh admin in a fresh company."
  @spec admin() :: t()
  def admin, do: %__MODULE__{id: Ash.UUID.generate(), company_id: Ash.UUID.generate()}

  @doc "A fresh user who may not manage API clients."
  @spec worker() :: t()
  def worker, do: %{admin() | role: :worker}

  @doc "An admin with id `id`, such as one of the fixed ids above, in `company_id`."
  @spec with_id(String.t(), String.t()) :: t()
  def with_id(id, company_id \\ Ash.UUID.generate()), do: %__MODULE__{id: id, company_id: company_id}

  @doc "Loads an owner the way `c:ApiGatehouse.Server.load_owner/2` would."
  @spec load(String.t(), String.t()) :: {:ok, t() | map() | nil} | {:error, term()}
  def load(@unloadable, _company_id), do: {:error, :not_a_company_admin}
  def load(@loads_as_nil, _company_id), do: {:ok, nil}

  def load(@in_other_company, _company_id), do: {:ok, %__MODULE__{id: @in_other_company, company_id: Ash.UUID.generate()}}

  def load(@without_company, _company_id), do: {:ok, %{id: @without_company}}
  def load(owner_id, company_id), do: {:ok, %__MODULE__{id: owner_id, company_id: company_id}}
end
