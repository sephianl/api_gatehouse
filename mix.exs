defmodule ApiGatehouse.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/sephianl/api_gatehouse"

  def project do
    [
      app: :api_gatehouse,
      version: @version,
      elixir: "~> 1.17",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      source_url: @source_url,
      docs: docs(),
      dialyzer: [
        plt_add_apps: [:ex_unit, :mix],
        plt_local_path: "priv/plts",
        plt_core_path: "priv/plts"
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto],
      mod: {ApiGatehouse.Application, []}
    ]
  end

  defp description do
    "OAuth 2.0 authorization server for machine-to-machine API access (client_credentials " <>
      "and refresh_token grants, RFC 7009 revocation, bearer authentication, rate limiting, " <>
      "read-only scope policy) for Ash and Phoenix apps."
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib mix.exs README.md LICENSE .formatter.exs)
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      extras: ["README.md", "LICENSE"]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]

  defp deps do
    [
      # 3.38.0 fixes CVE-2026-124283.
      {:ash, "~> 3.38"},
      {:plug, "~> 1.17"},
      {:jason, "~> 1.4"},
      {:hammer, "~> 7.5"},
      {:remote_ip, "~> 1.2"},
      {:bcrypt_elixir, "~> 3.0"},
      # Test router only: the library's plugs need nothing from Phoenix.
      {:phoenix, "~> 1.7", optional: true},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:styler, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:dialyxir, ">= 0.0.0", only: [:dev, :test], runtime: false},
      {:simple_sat, ">= 0.0.0", only: [:dev, :test]},
      {:sourceror, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
