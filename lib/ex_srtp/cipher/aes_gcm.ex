defmodule ExSRTP.Cipher.AesGcm do
  @moduledoc """
  """

  import Bitwise
  import ExSRTP.KeyDerivation

  @type t :: %__MODULE__{
          profile: :aes_gcm_128_16_auth,
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

    def encrypt_rtcp(cipher, data, index) do
      <<header::binary-size(4), ssrc::32, plain_text::binary>> = data

      iv = bxor(ssrc <<< 48 ||| index, cipher.rtcp_salt)
      iv = <<iv::96>>

      {cipher_text, auth_tag} =
        :crypto.crypto_one_time_aead(
          :aes_128_gcm,
          cipher.rtcp_key,
          iv,
          plain_text,
          <<header::binary, ssrc::32>>,
          true
        )

      <<header::binary, ssrc::32, cipher_text::binary, auth_tag::binary, 1::1, index::31>>
    end

    def decrypt_rtcp(cipher, data) do
      tag_length = 16
      cipher_length = byte_size(data) - tag_length - 12

      <<header::binary-size(4), ssrc::32, cipher_text::binary-size(cipher_length),
        auth_tag::binary-size(tag_length), _::1, index::31>> = data

      iv = bxor(ssrc <<< 48 ||| index, cipher.rtcp_salt)
      iv = <<iv::96>>

      case :crypto.crypto_one_time_aead(
             :aes_128_gcm,
             cipher.rtcp_key,
             iv,
             cipher_text,
             <<header::binary, ssrc::32>>,
             auth_tag,
             false
           ) do
        :error ->
          {:error, :authentication_failed}

        plain_text ->
          {:ok, <<header::binary, ssrc::32, plain_text::binary>>}
      end
    end

    def tag_size(_cipher), do: 0

    defp initialization_vector(salt, ssrc, roc, seq) do
      iv = ssrc <<< 48 ||| roc <<< 16 ||| seq
      <<bxor(iv, salt)::96>>
    end
  end
end
