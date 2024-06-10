defmodule SimpleTelemetryWeb.HelloJSON do

  def hello(%{name: name}) do
    %{message: "Hello " <> name}
  end

end
