defmodule SimpleTelemetry.Repo do
  use Ecto.Repo,
    otp_app: :simple_telemetry,
    adapter: Ecto.Adapters.Postgres
end
