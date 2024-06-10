defmodule SimpleTelemetry.FarmTest do
  use SimpleTelemetry.DataCase

  alias SimpleTelemetry.Farm

  describe "dogs" do
    alias SimpleTelemetry.Farm.Dog

    import SimpleTelemetry.FarmFixtures

    @invalid_attrs %{breed: nil, weight: nil}

    test "list_dogs/0 returns all dogs" do
      dog = dog_fixture()
      assert Farm.list_dogs() == [dog]
    end

    test "get_dog!/1 returns the dog with given id" do
      dog = dog_fixture()
      assert Farm.get_dog!(dog.id) == dog
    end

    test "create_dog/1 with valid data creates a dog" do
      valid_attrs = %{breed: "some breed", weight: 42}

      assert {:ok, %Dog{} = dog} = Farm.create_dog(valid_attrs)
      assert dog.breed == "some breed"
      assert dog.weight == 42
    end

    test "create_dog/1 with invalid data returns error changeset" do
      assert {:error, %Ecto.Changeset{}} = Farm.create_dog(@invalid_attrs)
    end

    test "update_dog/2 with valid data updates the dog" do
      dog = dog_fixture()
      update_attrs = %{breed: "some updated breed", weight: 43}

      assert {:ok, %Dog{} = dog} = Farm.update_dog(dog, update_attrs)
      assert dog.breed == "some updated breed"
      assert dog.weight == 43
    end

    test "update_dog/2 with invalid data returns error changeset" do
      dog = dog_fixture()
      assert {:error, %Ecto.Changeset{}} = Farm.update_dog(dog, @invalid_attrs)
      assert dog == Farm.get_dog!(dog.id)
    end

    test "delete_dog/1 deletes the dog" do
      dog = dog_fixture()
      assert {:ok, %Dog{}} = Farm.delete_dog(dog)
      assert_raise Ecto.NoResultsError, fn -> Farm.get_dog!(dog.id) end
    end

    test "change_dog/1 returns a dog changeset" do
      dog = dog_fixture()
      assert %Ecto.Changeset{} = Farm.change_dog(dog)
    end
  end
end
