defmodule SimpleTelemetryWeb.DogControllerTest do
  use SimpleTelemetryWeb.ConnCase

  import SimpleTelemetry.FarmFixtures

  alias SimpleTelemetry.Farm.Dog

  @create_attrs %{
    breed: "some breed",
    weight: 42
  }
  @update_attrs %{
    breed: "some updated breed",
    weight: 43
  }
  @invalid_attrs %{breed: nil, weight: nil}

  setup %{conn: conn} do
    {:ok, conn: put_req_header(conn, "accept", "application/json")}
  end

  describe "index" do
    test "lists all dogs", %{conn: conn} do
      conn = get(conn, ~p"/api/dogs")
      assert json_response(conn, 200)["data"] == []
    end
  end

  describe "create dog" do
    test "renders dog when data is valid", %{conn: conn} do
      conn = post(conn, ~p"/api/dogs", dog: @create_attrs)
      assert %{"id" => id} = json_response(conn, 201)["data"]

      conn = get(conn, ~p"/api/dogs/#{id}")

      assert %{
               "id" => ^id,
               "breed" => "some breed",
               "weight" => 42
             } = json_response(conn, 200)["data"]
    end

    test "renders errors when data is invalid", %{conn: conn} do
      conn = post(conn, ~p"/api/dogs", dog: @invalid_attrs)
      assert json_response(conn, 422)["errors"] != %{}
    end
  end

  describe "update dog" do
    setup [:create_dog]

    test "renders dog when data is valid", %{conn: conn, dog: %Dog{id: id} = dog} do
      conn = put(conn, ~p"/api/dogs/#{dog}", dog: @update_attrs)
      assert %{"id" => ^id} = json_response(conn, 200)["data"]

      conn = get(conn, ~p"/api/dogs/#{id}")

      assert %{
               "id" => ^id,
               "breed" => "some updated breed",
               "weight" => 43
             } = json_response(conn, 200)["data"]
    end

    test "renders errors when data is invalid", %{conn: conn, dog: dog} do
      conn = put(conn, ~p"/api/dogs/#{dog}", dog: @invalid_attrs)
      assert json_response(conn, 422)["errors"] != %{}
    end
  end

  describe "delete dog" do
    setup [:create_dog]

    test "deletes chosen dog", %{conn: conn, dog: dog} do
      conn = delete(conn, ~p"/api/dogs/#{dog}")
      assert response(conn, 204)

      assert_error_sent 404, fn ->
        get(conn, ~p"/api/dogs/#{dog}")
      end
    end
  end

  defp create_dog(_) do
    dog = dog_fixture()
    %{dog: dog}
  end
end
