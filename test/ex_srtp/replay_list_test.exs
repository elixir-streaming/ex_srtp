defmodule ExSRTP.ReplayListTest do
  use ExUnit.Case, async: true

  alias ExSRTP.ReplayList

  test "replay list check and update" do
    replay = ReplayList.new(64)

    {:ok, replay} = ReplayList.check_and_update(replay, 100)
    assert replay.max == 100
    assert replay.mask == 1

    {:ok, replay} = ReplayList.check_and_update(replay, 102)
    assert replay.max == 102
    assert replay.mask == 0b101

    {:ok, replay} = ReplayList.check_and_update(replay, 99)
    assert replay.max == 102
    assert replay.mask == 0b1101

    assert {:error, :replay} = ReplayList.check_and_update(replay, 100)
    assert {:error, :too_old} = ReplayList.check_and_update(replay, 15)

    {:ok, replay} = ReplayList.check_and_update(replay, 200)
    assert replay.max == 200
    assert replay.mask == 1
  end
end
