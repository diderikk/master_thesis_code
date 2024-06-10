defmodule SimpleTelemetry.FarmFixtures do
  @moduledoc """
  This module defines test helpers for creating
  entities via the `SimpleTelemetry.Farm` context.
  """

  @doc """
  Generate a dog.
  """
  def dog_fixture(attrs \\ %{}) do
    {:ok, dog} =
      attrs
      |> Enum.into(%{
        breed: "some breed",
        weight: 42
      })
      |> SimpleTelemetry.Farm.create_dog()

    dog
  end
end
