defmodule ExSRTP.KeyDerivationTest do
  use ExUnit.Case, async: true

  alias ExSRTP.KeyDerivation

  test "key derivation" do
    master_key = :binary.decode_hex("E1F97A0D3E018BE0D64FA32C06DE4139")
    master_salt = :binary.decode_hex("0EC675AD498AFEEBB6960B3AABE6")

    rtp_session_key = KeyDerivation.aes_cm_derive(0x0, master_key, master_salt, 128)
    assert rtp_session_key == :binary.decode_hex("C61E7A93744F39EE10734AFE3FF7A087")

    rtp_auth_key = KeyDerivation.aes_cm_derive(0x1, master_key, master_salt, 128)
    assert rtp_auth_key == :binary.decode_hex("CEBE321F6FF7716B6FD4AB49AF256A15")

    rtp_salt = KeyDerivation.aes_cm_derive(0x2, master_key, master_salt, 112)
    assert rtp_salt == :binary.decode_hex("30CBBC08863D8C85D49DB34A9AE1")
  end
end
