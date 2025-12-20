defmodule ExSRTPTest do
  use ExUnit.Case, async: true

  @key "mysecretkey12345"
  @salt "mysaltvalue123"

  setup do
    srtp = ExSRTP.new(%ExSRTP.Policy{master_key: @key, master_salt: @salt})

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

    compound_packet = [
      %ExRTCP.Packet.SenderReport{
        ssrc: 0x89A1FF87,
        ntp_timestamp: 0x1234567890ABCDEF,
        rtp_timestamp: 123_456,
        packet_count: 100,
        octet_count: 200,
        reports: []
      },
      %ExRTCP.Packet.Goodbye{sources: [0x89A1FF87]}
    ]

    {:ok, srtp: srtp, packet: packet, compound_packet: compound_packet}
  end

  test "protect packet", %{srtp: srtp, packet: packet} do
    {protected_packet, _srtp} = ExSRTP.protect(packet, srtp)

    assert protected_packet ==
             <<128, 96, 0, 1, 0, 1, 226, 64, 137, 161, 255, 135, 146, 221, 94, 142, 7, 197, 169,
               172, 155, 23, 74, 128, 181, 142, 45>>
  end

  test "protect rtcp", %{srtp: srtp, compound_packet: compound_packet} do
    {protected_rtcp, _srtp} = ExSRTP.protect_rtcp(compound_packet, srtp)

    expected =
      <<128, 200, 0, 6, 137, 161, 255, 135, 235, 3, 169, 113, 236, 134, 217, 36, 127, 210, 78,
        156, 66, 244, 203, 218, 58, 80, 24, 60, 28, 171, 30, 89, 192, 155, 19, 59, 128, 0, 0, 1,
        139, 226, 152, 17, 40, 71, 251, 110, 11, 235>>

    assert protected_rtcp == expected
  end

  test "unprotect rtp", %{srtp: srtp, packet: packet} do
    protected_packet =
      <<128, 96, 0, 1, 0, 1, 226, 64, 137, 161, 255, 135, 146, 221, 94, 142, 7, 197, 169, 172,
        155, 23, 74, 128, 181, 142, 45>>

    assert {:ok, unprotected_packet, _srtp} = ExSRTP.unprotect(protected_packet, srtp)
    assert unprotected_packet == packet
  end

  test "unprotect rtcp", %{srtp: srtp} do
    protected_rtcp =
      <<128, 200, 0, 6, 137, 161, 255, 135, 235, 3, 169, 113, 236, 134, 217, 36, 127, 210, 78,
        156, 66, 244, 203, 218, 58, 80, 24, 60, 28, 171, 30, 89, 192, 155, 19, 59, 128, 0, 0, 1,
        139, 226, 152, 17, 40, 71, 251, 110, 11, 235>>

    assert {:ok, unprotected_packets, _srtp} = ExSRTP.unprotect_rtcp(protected_rtcp, srtp)

    expected_packets = [
      %ExRTCP.Packet.SenderReport{
        ssrc: 0x89A1FF87,
        ntp_timestamp: 0x1234567890ABCDEF,
        rtp_timestamp: 123_456,
        packet_count: 100,
        octet_count: 200,
        reports: []
      },
      %ExRTCP.Packet.Goodbye{sources: [0x89A1FF87]}
    ]

    assert unprotected_packets == expected_packets
  end
end
