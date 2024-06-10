defmodule SimpleTelemetryWeb.DogJSON do
  alias SimpleTelemetry.Farm.Dog

  @doc """
  Renders a list of dogs.
  """
  def index(%{dogs: dogs}) do
    %{data: for(dog <- dogs, do: data(dog))}
  end

  @doc """
  Renders a single dog.
  """
  def show(%{dog: dog}) do
    %{data: data(dog)}
  end

  defp data(%Dog{} = dog) do
    %{
      id: dog.id,
      breed: dog.breed,
      weight: dog.weight
    }
  end
end
