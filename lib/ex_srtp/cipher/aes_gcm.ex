defmodule ExSRTP.Cipher.AesGcm do
  @moduledoc """
  """

  import Bitwise
  import ExSRTP.KeyDerivation

  @type t :: %__MODULE__{
          profile: :aes128_gcm | :aes256_gcm,
          rtp_key: binary(),
          rtp_salt: binary(),
          rtcp_key: binary(),
          rtcp_salt: binary()
        }

  defstruct [:profile, :rtp_key, :rtp_salt, :rtcp_key, :rtcp_salt]

  @spec new(atom(), master_key :: binary(), master_salt :: binary()) :: t()
  def new(profile, master_key, master_salt) do
    %__MODULE__{
      profile: profile,
      rtp_key: aes_cm_derive(0x0, master_key, master_salt, 128),
      rtp_salt: aes_cm_derive(0x2, master_key, master_salt, 96) |> :crypto.bytes_to_integer(),
      rtcp_key: aes_cm_derive(0x3, master_key, master_salt, 128),
      rtcp_salt: aes_cm_derive(0x5, master_key, master_salt, 96) |> :crypto.bytes_to_integer()
    }
  end

  defimpl ExSRTP.Cipher do
    def encrypt_rtp(cipher, packet, roc) do
      header = ExRTP.Packet.encode(%{packet | payload: <<>>})

      {cipher_text, auth_tag} =
        :crypto.crypto_one_time_aead(
          :aes_128_gcm,
          cipher.rtp_key,
          initialization_vector(cipher.rtp_salt, packet.ssrc, roc, packet.sequence_number),
          packet.payload,
          header,
          true
        )

      [header, cipher_text, auth_tag]
    end

    def decrypt_rtp(cipher, data, packet, roc) do
      header_size = byte_size(data) - byte_size(packet.payload)
      cipher_length = byte_size(packet.payload) - 16
      tag_length = 16

      case :crypto.crypto_one_time_aead(
             :aes_128_gcm,
             cipher.rtp_key,
             initialization_vector(cipher.rtp_salt, packet.ssrc, roc, packet.sequence_number),
             binary_part(packet.payload, 0, cipher_length),
             binary_part(data, 0, header_size),
             binary_part(packet.payload, cipher_length, tag_length),
             false
           ) do
        :error ->
          {:error, :authentication_failed}

        plain_text ->
          {:ok, %{packet | payload: plain_text}}
      end
    end

    def encrypt_rtcp(_cipher, _data, _index) do
      raise "not implemented"
    end

    def decrypt_rtcp(_cipher, _data) do
      raise "not implemented"
    end

    def tag_size(_cipher), do: 0

    defp initialization_vector(salt, ssrc, roc, seq) do
      iv = ssrc <<< 48 ||| roc <<< 32 ||| seq
      <<bxor(iv, salt)::96>>
    end
  end
end
