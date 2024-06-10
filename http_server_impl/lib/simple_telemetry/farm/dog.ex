defmodule SimpleTelemetry.Farm.Dog do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "dogs" do
    field :breed, :string
    field :weight, :integer

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(dog, attrs) do
    dog
    |> cast(attrs, [:breed, :weight])
    |> validate_required([:breed, :weight])
  end
end
