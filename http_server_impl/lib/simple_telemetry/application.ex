defmodule SimpleTelemetry.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    :opentelemetry_cowboy.setup()
    OpentelemetryPhoenix.setup(adapter: :cowboy2)
    OpentelemetryEcto.setup([:simple_telemetry, :repo])

    children = [
      SimpleTelemetryWeb.Telemetry,
      SimpleTelemetry.Repo,
      {DNSCluster, query: Application.get_env(:simple_telemetry, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: SimpleTelemetry.PubSub},
      # Start a worker by calling: SimpleTelemetry.Worker.start_link(arg)
      # {SimpleTelemetry.Worker, arg},
      # Start to serve requests, typically the last entry
      SimpleTelemetryWeb.Endpoint
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: SimpleTelemetry.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    SimpleTelemetryWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
