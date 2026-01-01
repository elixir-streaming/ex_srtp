defmodule ExSRTP.Cipher.AesCmHmacSha1 do
  @moduledoc """
  Implementation of SRTP cipher using AES Counter Mode for encryption
  and HMAC-SHA1 for authentication, as specified in RFC 3711.
  """

  import ExSRTP.KeyDerivation
  import Bitwise

  @type t :: %__MODULE__{
          profile: ExSRTP.Policy.profile(),
          rtp_session_key: binary(),
          rtp_auth_key: binary(),
          rtp_salt: binary(),
          rtcp_session_key: binary(),
          rtcp_auth_key: binary(),
          rtcp_salt: binary()
        }

  defstruct [
    :profile,
    :rtp_session_key,
    :rtp_auth_key,
    :rtp_salt,
    :rtcp_session_key,
    :rtcp_auth_key,
    :rtcp_salt
  ]

  @spec new(
          profile :: ExSRTP.Policy.profile(),
          master_key :: binary(),
          master_salt :: binary()
        ) :: t()
  def new(profile, master_key, master_salt) do
    %__MODULE__{
      profile: profile,
      rtp_session_key: aes_cm_derive(0x0, master_key, master_salt, 128),
      rtp_auth_key: aes_cm_derive(0x1, master_key, master_salt, 160),
      rtp_salt:
        aes_cm_derive(0x2, master_key, master_salt, 112)
        |> :crypto.bytes_to_integer()
        |> Bitwise.bsl(16),
      rtcp_session_key: aes_cm_derive(0x3, master_key, master_salt, 128),
      rtcp_auth_key: aes_cm_derive(0x4, master_key, master_salt, 160),
      rtcp_salt:
        aes_cm_derive(0x5, master_key, master_salt, 112)
        |> :crypto.bytes_to_integer()
        |> Bitwise.bsl(16)
    }
  end

  defimpl ExSRTP.Cipher do
    def encrypt_rtp(cipher, packet, roc) do
      header = ExRTP.Packet.encode(%{packet | payload: <<>>})
      idx = packet.ssrc <<< 48 ||| roc <<< 16 ||| packet.sequence_number
      iv = bxor(cipher.rtp_salt, idx <<< 16)

      payload =
        :crypto.crypto_one_time(:aes_128_ctr, cipher.rtp_session_key, <<iv::128>>, packet.payload,
          encrypt: true
        )

      auth_tag =
        :crypto.macN(
          :hmac,
          :sha,
          cipher.rtp_auth_key,
          [header, payload, <<roc::32>>],
          tag_size(cipher)
        )

      [header, payload, auth_tag]
    end

    def decrypt_rtp(cipher, data, packet, roc) do
      tag_size = tag_size(cipher)
      header_size = byte_size(data) - byte_size(packet.payload)

      <<encrypted_data::binary-size(byte_size(data) - tag_size), tag::binary>> = data
      new_tag = generate_srtp_auth_tag(cipher, encrypted_data, roc)

      if tag == new_tag do
        idx = packet.ssrc <<< 48 ||| roc <<< 16 ||| packet.sequence_number
        iv = bxor(cipher.rtp_salt, idx <<< 16)

        payload =
          :crypto.crypto_one_time(
            :aes_128_ctr,
            cipher.rtp_session_key,
            <<iv::128>>,
            binary_part(encrypted_data, header_size, byte_size(encrypted_data) - header_size),
            encrypt: false
          )

        {:ok, %{packet | payload: payload}}
      else
        {:error, :auth_failed}
      end
    end

    def encrypt_rtcp(cipher, data, index) do
      <<header::binary-size(4), ssrc::32, payload::binary>> = data
      iv = bxor(cipher.rtcp_salt, ssrc <<< 64 ||| index <<< 16)

      payload =
        :crypto.crypto_one_time(:aes_128_ctr, cipher.rtcp_session_key, <<iv::128>>, payload,
          encrypt: true
        )

      rtcp_packet = <<header::binary, ssrc::32, payload::binary, 1::1, index::31>>
      auth_tag = generate_srtcp_auth_tag(cipher, rtcp_packet)
      <<rtcp_packet::binary, auth_tag::binary>>
    end

    def decrypt_rtcp(cipher, data) do
      tag_size = tag_size(cipher)
      authenticated_data_size = byte_size(data) - tag_size

      <<rtcp_data::binary-size(authenticated_data_size - 4), e::1, index::31, tag::binary>> = data

      new_tag = generate_srtcp_auth_tag(cipher, binary_part(data, 0, authenticated_data_size))

      cond do
        new_tag != tag ->
          {:error, :authentication_failed}

        e == 0 ->
          {:ok, rtcp_data}

        true ->
          <<header::32, ssrc::32, encrypted_data::binary>> = rtcp_data
          iv = bxor(cipher.rtcp_salt, ssrc <<< 64 ||| index <<< 16)

          decrypted_data =
            :crypto.crypto_one_time(
              :aes_128_ctr,
              cipher.rtcp_session_key,
              <<iv::128>>,
              encrypted_data,
              encrypt: false
            )

          {:ok, <<header::32, ssrc::32, decrypted_data::binary>>}
      end
    end

    defp generate_srtp_auth_tag(cipher, data, roc) do
      :crypto.macN(
        :hmac,
        :sha,
        cipher.rtp_auth_key,
        [data, <<roc::32>>],
        tag_size(cipher)
      )
    end

    defp generate_srtcp_auth_tag(cipher, data) do
      :crypto.macN(:hmac, :sha, cipher.rtcp_auth_key, data, tag_size(cipher))
    end

    def tag_size(%{profile: :aes_cm_128_hmac_sha1_80}), do: 10
    def tag_size(%{profile: :aes_cm_128_hmac_sha1_32}), do: 4
  end
end
