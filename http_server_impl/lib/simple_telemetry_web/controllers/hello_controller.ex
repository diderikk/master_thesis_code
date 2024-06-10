defmodule SimpleTelemetryWeb.HelloController do
  use SimpleTelemetryWeb, :controller
  require OpenTelemetry.Tracer, as: Tracer

  def hello(conn, %{"name" => name}) do
    Tracer.with_span("hello_request") do
      Tracer.set_attribute(:name, name)

      render(conn, :hello, name: name)
    end
  end

  def hello(conn, _params) do
    hello(conn, %{"name" => "World"})
  end
end
