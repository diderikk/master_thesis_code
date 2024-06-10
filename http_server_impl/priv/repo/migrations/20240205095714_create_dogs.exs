defmodule SimpleTelemetry.Repo.Migrations.CreateDogs do
  use Ecto.Migration

  def change do
    create table(:dogs, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :breed, :string
      add :weight, :integer

      timestamps(type: :utc_datetime)
    end
  end
end
