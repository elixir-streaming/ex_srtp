defmodule ExSRTPTest do
  use ExUnit.Case, async: true

  @key "mysecretkey12345"
  @salt "mysaltvalue123"

  setup do
    srtp = ExSRTP.new(%ExSRTP.Policy{master_key: @key, master_salt: @salt})
    {:ok, srtp: srtp}
  end

  test "protect packet", %{srtp: srtp} do
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

    {protected_packet, _srtp_after} = ExSRTP.protect(packet, srtp)

    assert protected_packet ==
             <<128, 96, 0, 1, 0, 1, 226, 64, 137, 161, 255, 135, 146, 221, 94, 142, 7, 197, 169,
               172, 155, 23, 74, 128, 181, 142, 45>>
  end

  test "protect rtcp", %{srtp: srtp} do
    packets = [
      %ExRTCP.Packet.SenderReport{
        ssrc: 0x89A1FF87,
        ntp_timestamp: 0x1234567890ABCDEF,
        rtp_timestamp: 123_456,
        packet_count: 100,
        octet_count: 200,
        reports: []
      },
      %ExRTCP.Packet.Goodbye{
        sources: [0x89A1FF87],
        reason: "Goodbye"
      }
    ]

    {protected_rtcp, _srtp} = ExSRTP.protect_rtcp(packets, srtp)

    expected =
      <<128, 200, 0, 6, 137, 161, 255, 135, 235, 3, 169, 113, 236, 134, 217, 36, 127, 210, 78,
        156, 66, 244, 203, 218, 58, 80, 24, 60, 28, 171, 30, 91, 192, 155, 19, 59, 255, 44, 189,
        211, 163, 16, 68, 176, 7, 128, 0, 0, 1, 57, 9, 25, 200, 123, 251, 29, 169, 118, 44>>

    assert protected_rtcp == expected
  end
end
