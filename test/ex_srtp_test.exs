defmodule ExSRTPTest do
  use ExUnit.Case, async: true

  @key "mysecretkey12345"
  @salt "mysaltvalue123"

  setup do
    srtp = ExSRTP.new!(%ExSRTP.Policy{master_key: @key, master_salt: @salt})

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
    assert {:ok, protected_packet, _srtp} = ExSRTP.protect(packet, srtp)

    assert IO.iodata_to_binary(protected_packet) ==
             <<128, 96, 0, 1, 0, 1, 226, 64, 137, 161, 255, 135, 146, 221, 94, 142, 7, 197, 169,
               172, 155, 23, 74, 128, 181, 142, 45>>
  end

  test "protect rtcp", %{srtp: srtp, compound_packet: compound_packet} do
    assert {:ok, protected_rtcp, _srtp} = ExSRTP.protect_rtcp(compound_packet, srtp)

    expected =
      <<128, 200, 0, 6, 137, 161, 255, 135, 235, 3, 169, 113, 236, 134, 217, 36, 127, 210, 78,
        156, 66, 244, 203, 218, 58, 80, 24, 60, 28, 171, 30, 89, 192, 155, 19, 59, 128, 0, 0, 1,
        139, 226, 152, 17, 40, 71, 251, 110, 11, 235>>

    assert protected_rtcp == expected
  end

  describe "unprotect rtp" do
    test "unprotect rtp", %{srtp: srtp, packet: packet} do
      protected_packet =
        <<128, 96, 0, 1, 0, 1, 226, 64, 137, 161, 255, 135, 146, 221, 94, 142, 7, 197, 169, 172,
          155, 23, 74, 128, 181, 142, 45>>

      assert {:ok, unprotected_packet, _srtp} = ExSRTP.unprotect(protected_packet, srtp)
      assert unprotected_packet == packet
    end

    test "unprotect replayed rtp", %{srtp: srtp, packet: packet} do
      protected_packet =
        <<128, 96, 0, 1, 0, 1, 226, 64, 137, 161, 255, 135, 146, 221, 94, 142, 7, 197, 169, 172,
          155, 23, 74, 128, 181, 142, 45>>

      assert {:ok, unprotected_packet, srtp} = ExSRTP.unprotect(protected_packet, srtp)
      assert {:error, :replay} = ExSRTP.unprotect(protected_packet, srtp)
      assert unprotected_packet == packet
    end
  end

  describe "unprotect rtcp" do
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

    test "fail on replayed rtcp", %{srtp: srtp} do
      protected_rtcp =
        <<128, 200, 0, 6, 137, 161, 255, 135, 235, 3, 169, 113, 236, 134, 217, 36, 127, 210, 78,
          156, 66, 244, 203, 218, 58, 80, 24, 60, 28, 171, 30, 89, 192, 155, 19, 59, 128, 0, 0, 1,
          139, 226, 152, 17, 40, 71, 251, 110, 11, 235>>

      assert {:ok, _unprotected_packets, srtp} = ExSRTP.unprotect_rtcp(protected_rtcp, srtp)
      assert {:error, :replay} = ExSRTP.unprotect_rtcp(protected_rtcp, srtp)
    end
  end

  for profile <- [:aes_cm_128_hmac_sha1_80, :aes_cm_128_hmac_sha1_32] do
    describe "Protect/unprotect: #{profile}" do
      setup do
        srtp =
          ExSRTP.new!(%ExSRTP.Policy{
            master_key: @key,
            master_salt: @salt,
            rtp_profile: unquote(profile),
            rtcp_profile: unquote(profile)
          })

        {:ok, srtp: srtp}
      end

      test "protect and unprotect", %{srtp: srtp} do
        original_packets = packets(10000)
        {encrypted_packets, srtp} = Enum.map_reduce(original_packets, srtp, &ExSRTP.protect!/2)
        encrypted_packets = Enum.map(encrypted_packets, &IO.iodata_to_binary/1)

        original_packets
        |> Enum.zip(encrypted_packets)
        |> Enum.reduce(srtp, fn {original_packet, protected_packet}, srtp ->
          {unprotected_packet, srtp} = ExSRTP.unprotect!(protected_packet, srtp)
          assert unprotected_packet == original_packet
          srtp
        end)
      end

      test "protect and unprotect out of order", %{srtp: srtp} do
        original_packets = packets(32_000)
        {encrypted_packets, srtp} = Enum.map_reduce(original_packets, srtp, &ExSRTP.protect!/2)
        encrypted_packets = Enum.map(encrypted_packets, &IO.iodata_to_binary/1)

        # keep the first packet in order to invalid initial ROC value
        [first_packet | original_packets] = original_packets
        [first_encrypted | encrypted_packets] = encrypted_packets

        shuffled =
          original_packets
          |> Enum.zip(encrypted_packets)
          |> Enum.chunk_every(64)
          |> Enum.flat_map(&Enum.shuffle(&1))

        [{first_packet, first_encrypted} | shuffled]
        |> Enum.reduce(srtp, fn {original_packet, protected_packet}, srtp ->
          {unprotected_packet, srtp} = ExSRTP.unprotect!(protected_packet, srtp)
          assert unprotected_packet == original_packet
          srtp
        end)
      end
    end
  end

  defp packets(size) do
    packet = %ExRTP.Packet{
      version: 2,
      padding: false,
      extension: false,
      marker: false,
      payload_type: 96,
      sequence_number: :rand.uniform(65_535),
      timestamp: 123_456,
      ssrc: 0x89A1FF87,
      payload: rand_payload()
    }

    Stream.iterate(packet, fn packet ->
      %ExRTP.Packet{
        packet
        | sequence_number: rem(packet.sequence_number + 1, 65_536),
          timestamp: packet.timestamp + 3000,
          payload: rand_payload()
      }
    end)
    |> Enum.take(size)
  end

  defp rand_payload() do
    len = :rand.uniform(1000) + 500
    :crypto.strong_rand_bytes(len)
  end
end
