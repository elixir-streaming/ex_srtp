defmodule ExSRTP.Cipher.AesGcmTest do
  use ExUnit.Case, async: true

  alias ExSRTP.Cipher.AesGcm

  describe "aes gcm 128" do
    setup do
      master_key = :crypto.strong_rand_bytes(16)
      master_salt = :crypto.strong_rand_bytes(12)
      %{cipher: AesGcm.new(:aes_gcm_128_16_auth, master_key, master_salt)}
    end

    test "protect/unprotect rtp", %{cipher: cipher} do
      packet =
        ExRTP.Packet.new(:crypto.strong_rand_bytes(1200),
          ssrc: 0x12345678,
          sequence_number: 0x3456
        )

      roc = 0x00001234
      encrypted_data = ExSRTP.Cipher.encrypt_rtp(cipher, packet, roc)

      assert {:ok, enc_packet} = ExRTP.Packet.decode(IO.iodata_to_binary(encrypted_data))

      assert {:ok, decrypted_packet} =
               ExSRTP.Cipher.decrypt_rtp(
                 cipher,
                 IO.iodata_to_binary(encrypted_data),
                 enc_packet,
                 roc
               )

      assert decrypted_packet == packet
    end

    test "protect/unprotect rtcp", %{cipher: cipher} do
      ssrc = 0x12345678
      index = 0x00001234

      rtcp_packet =
        %ExRTCP.Packet.SenderReport{
          ssrc: ssrc,
          ntp_timestamp: 0x1122334455667788,
          rtp_timestamp: 0x99AABBCC,
          packet_count: 100,
          octet_count: 200
        }

      data = ExRTCP.CompoundPacket.encode([rtcp_packet])

      encrypted_data = ExSRTP.Cipher.encrypt_rtcp(cipher, data, index)

      assert {:ok, decrypted_data} = ExSRTP.Cipher.decrypt_rtcp(cipher, encrypted_data)
      assert decrypted_data == data
    end
  end
end
