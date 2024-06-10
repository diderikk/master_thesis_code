defmodule SimpleTelemetryWeb.Router do
  use SimpleTelemetryWeb, :router

  pipeline :api do
    plug :accepts, ["json"]
  end

  scope "/api", SimpleTelemetryWeb do
    pipe_through :api

    get "/hello/:name", HelloController, :hello
    resources "/dogs", DogController, except: [:new, :edit]
  end


  if Mix.env() == :dev do
    pipe_through :api
    scope "/" do
      get "/", SimpleTelemetryWeb.HelloController, :hello
    end
  end
end
