import Config

config :ash,
  allow_forbidden_field_for_relationships_by_default?: true,
  include_embedded_source_by_default?: false,
  show_keysets_for_all_actions?: false,
  default_page_type: :keyset,
  policies: [no_filter_static_forbidden_reads?: false],
  keep_read_action_loads_when_loading?: false,
  default_actions_require_atomic?: true,
  read_action_after_action_hooks_in_order?: true,
  bulk_actions_default_to_errors?: true,
  transaction_rollback_on_error?: true,
  default_string_length_count: :codepoints

if config_env() == :test do
  config :api_gatehouse,
    ash_domains: [
      ApiGatehouse.Test.OAuth,
      ApiGatehouse.Test.Catalog,
      ApiGatehouse.Test.Workshop,
      ApiGatehouse.Test.Plain
    ],
    rate_limiter: ApiGatehouse.Test.RateLimiterStub

  config :ash, :disable_async?, true

  config :bcrypt_elixir, log_rounds: 4

  config :logger, level: :warning

  # What the README asks of hosts: Phoenix's own default leaves `client_secret` in its debug log.
  config :phoenix, :filter_parameters, ["password", "secret", "token"]
end
