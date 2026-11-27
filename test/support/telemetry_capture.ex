defmodule ApiGatehouse.Test.TelemetryCapture do
  @moduledoc """
  Sends the library's telemetry events to the test that attached, as
  `{:telemetry, event, measurements, metadata}` — only those its own process
  emitted, since handlers are global and async tests would otherwise see each
  other's. Under `Plug.Test` the plugs run in the test process.
  """

  @spec attach() :: :ok
  def attach do
    id = {__MODULE__, self(), make_ref()}

    :ok =
      :telemetry.attach_many(id, ApiGatehouse.Telemetry.events(), &__MODULE__.forward/4, self())

    ExUnit.Callbacks.on_exit(fn -> :telemetry.detach(id) end)
    :ok
  end

  @doc false
  @spec forward([atom()], map(), map(), pid()) :: :ok
  def forward(event, measurements, metadata, test) do
    if self() == test, do: send(test, {:telemetry, event, measurements, metadata})
    :ok
  end
end
