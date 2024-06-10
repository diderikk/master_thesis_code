defmodule SimpleTelemetryWeb.DogController do
  use SimpleTelemetryWeb, :controller
  require OpenTelemetry.Tracer, as: Tracer

  alias SimpleTelemetry.Farm
  alias SimpleTelemetry.Farm.Dog

  action_fallback SimpleTelemetryWeb.FallbackController

  def index(conn, _params) do
    dogs = Farm.list_dogs()
    render(conn, :index, dogs: dogs)
  end

  def create(conn, %{"dog" => dog_params}) do
    Tracer.with_span("dog_create_request") do
      dog = Tracer.with_span("insert_dog_into_database") do
        {:ok, %Dog{} = dog} = Farm.create_dog(dog_params)
        dog
      end
      conn
      |> put_status(:created)
      |> put_resp_header("location", ~p"/api/dogs/#{dog}")
      |> render(:show, dog: dog)
    end
  end

  def show(conn, %{"id" => id}) do
    Tracer.with_span("dog_show_request") do
      dog = Tracer.with_span("get_dog_from_database") do
        Farm.get_dog!(id)
      end
      render(conn, :show, dog: dog)
    end
  end

  def update(conn, %{"id" => id, "dog" => dog_params}) do
    dog = Farm.get_dog!(id)

    with {:ok, %Dog{} = dog} <- Farm.update_dog(dog, dog_params) do
      render(conn, :show, dog: dog)
    end
  end

  def delete(conn, %{"id" => id}) do
    dog = Farm.get_dog!(id)

    with {:ok, %Dog{}} <- Farm.delete_dog(dog) do
      send_resp(conn, :no_content, "")
    end
  end
end
