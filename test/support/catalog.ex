defmodule ApiGatehouse.Test.Catalog do
  @moduledoc "A host domain served over the API, with the read-only scope policy added as a host would add it."
  use Ash.Domain, fragments: [ApiGatehouse.ReadOnlyScopePolicy]

  resources do
    resource ApiGatehouse.Test.Widget
  end
end

defmodule ApiGatehouse.Test.Widget do
  @moduledoc """
  An API-backed resource over a per-process ETS table, with one action of each
  type, and a generic action, `:plant`, that writes by running `:create` with
  its own context passed on, as `Ash.Context.to_opts/2` does.
  """
  use Ash.Resource,
    domain: ApiGatehouse.Test.Catalog,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer]

  ets do
    private? true
  end

  code_interface do
    define :list, action: :list
    define :create, args: [:name], action: :create
    define :rename, args: [:name], action: :rename
    define :remove, action: :remove
    define :count_widgets, action: :count_widgets
    define :plant, args: [:name], action: :plant
  end

  actions do
    read :list do
      primary? true
    end

    create :create do
      accept [:name]
    end

    update :rename do
      accept [:name]
    end

    destroy :remove

    action :count_widgets, :integer do
      run fn _input, _context -> {:ok, 0} end
    end

    action :plant, :struct do
      constraints instance_of: __MODULE__

      argument :name, :string, allow_nil?: false

      run fn input, context ->
        __MODULE__.create(
          Ash.ActionInput.get_argument(input, :name),
          Ash.Context.to_opts(context)
        )
      end
    end
  end

  policies do
    policy always() do
      authorize_if actor_present()
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :name, :string do
      allow_nil? false
      public? true
    end
  end
end

defmodule ApiGatehouse.Test.Workshop do
  @moduledoc "A host domain without domain policies, whose resource carries the read-only policy itself."
  use Ash.Domain

  resources do
    resource ApiGatehouse.Test.Gadget
  end
end

defmodule ApiGatehouse.Test.Gadget do
  @moduledoc "A resource carrying `ApiGatehouse.ReadOnlyScopePolicy.Resource` beside its own policies."
  use Ash.Resource,
    domain: ApiGatehouse.Test.Workshop,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer],
    fragments: [ApiGatehouse.ReadOnlyScopePolicy.Resource]

  ets do
    private? true
  end

  code_interface do
    define :list, action: :read
    define :create, args: [:name], action: :create
  end

  actions do
    defaults [:read, create: [:name]]
  end

  policies do
    policy action_type([:read, :create]) do
      authorize_if actor_present()
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :name, :string do
      allow_nil? false
      public? true
    end
  end
end
