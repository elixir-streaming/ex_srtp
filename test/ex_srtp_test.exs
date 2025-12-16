defmodule ExSRTPTest do
  use ExUnit.Case, async: true

  @key "mysecretkey12345"
  @salt "mysaltvalue123"

  test "protect packet" do
    srtp = ExSRTP.new(master_key: @key, master_salt: @salt, ssrc: :any_inbound)

    packet = %ExRTP.Packet{
      version: 2,
      padding: false,
      extension: false,
      marker: false,
      payload_type: 96,
      sequence_number: 1,
      timestamp: 123_456,
      ssrc: 0x89A1FF87,
      payload: <<1, 2, 3, 4, 5>>
    }

    {protected_packet, _srtp_after} = ExSRTP.protect(srtp, packet)

    assert IO.iodata_to_binary(protected_packet) ==
             <<128, 96, 0, 1, 0, 1, 226, 64, 137, 161, 255, 135, 146, 221, 94, 142, 7, 197, 169,
               172, 155, 23, 74, 128, 181, 142, 45>>
  end
end
