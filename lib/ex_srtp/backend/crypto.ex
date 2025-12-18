defmodule ExSRTP.Backend.Crypto do
  @moduledoc """
  Implementation of `ExSRTP.Backend` using erlang `:crypto` module.
  """

  @behaviour ExSRTP.Backend

  import Bitwise

  @srtp_index_max Bitwise.bsl(1, 31)

  @type t :: %__MODULE__{
          rtp_profile: ExSRTP.Policy.profile(),
          rtcp_profile: ExSRTP.Policy.profile(),
          rtp_session_key: binary() | nil,
          rtp_auth_key: binary() | nil,
          rtp_salt: binary() | nil,
          rtcp_session_key: binary() | nil,
          rtcp_auth_key: binary() | nil,
          rtcp_salt: binary() | nil,
          contexts: %{non_neg_integer() => ExSRTP.Context.t()}
        }

  defstruct [
    :rtp_session_key,
    :rtp_auth_key,
    :rtp_salt,
    :rtcp_session_key,
    :rtcp_auth_key,
    :rtcp_salt,
    :rtp_profile,
    :rtcp_profile,
    contexts: %{}
  ]

  @impl true
  def init(%ExSRTP.Policy{} = policy) do
    {cipher_key, auth_key, cipher_salt, rtcp_session_key, rtcp_auth_key, rtcp_salt_key} =
      derive_keys(policy.master_key, policy.master_salt)

    %__MODULE__{
      rtp_profile: policy.rtp_profile || :aes_cm_128_hmac_sha1_80,
      rtp_session_key: cipher_key,
      rtp_auth_key: auth_key,
      rtp_salt: cipher_salt,
      rtcp_profile: policy.rtcp_profile || :aes_cm_128_hmac_sha1_80,
      rtcp_session_key: rtcp_session_key,
      rtcp_auth_key: rtcp_auth_key,
      rtcp_salt: rtcp_salt_key
    }
  end

  @impl true
  def protect(%{ssrc: ssrc} = packet, session) do
    ctx = session |> get_ctx(packet.ssrc) |> maybe_inc_roc(packet)

    idx = ctx.roc <<< 16 ||| packet.sequence_number
    iv = bxor(ctx.base_iv, idx <<< 16)

    payload =
      :crypto.crypto_one_time(:aes_128_ctr, session.rtp_session_key, <<iv::128>>, packet.payload,
        encrypt: true
      )

    packet = ExRTP.Packet.encode(%{packet | payload: payload})

    auth_tag =
      :crypto.macN(:hmac, :sha, session.rtp_auth_key, <<packet::binary, ctx.roc::32>>, 10)

    {<<packet::binary, auth_tag::binary>>,
     %{session | contexts: Map.put(session.contexts, ssrc, ctx)}}
  end

  @impl true
  def protect_rtcp(compound_packet, session) do
    # first rtcp packet must be SR or RR
    ssrc = List.first(compound_packet).ssrc
    ctx = get_ctx(session, ssrc)
    <<header::binary-size(8), payload::binary>> = ExRTCP.CompoundPacket.encode(compound_packet)

    payload =
      :crypto.crypto_one_time(
        :aes_128_ctr,
        session.rtcp_session_key,
        <<bxor(ctx.rtcp_base_iv, ctx.rtcp_idx <<< 16)::128>>,
        payload,
        encrypt: true
      )

    rtcp_packet = <<header::binary, payload::binary, 1::1, ctx.rtcp_idx::31>>
    auth_tag = :crypto.macN(:hmac, :sha, session.rtcp_auth_key, rtcp_packet, 10)

    ctx = %{ctx | rtcp_idx: rem(ctx.rtcp_idx + 1, @srtp_index_max)}
    session = %{session | contexts: Map.put(session.contexts, ssrc, ctx)}

    {<<rtcp_packet::binary, auth_tag::binary>>, session}
  end

  defp derive_keys(master_key, master_salt) do
    <<prefix::binary-size(7), byte::8, suffix::binary-size(6)>> = master_salt

    auth_iv = <<prefix::binary, bxor(1, byte), suffix::binary, 0::16>>
    salt_iv = <<prefix::binary, bxor(2, byte), suffix::binary, 0::16>>
    rtcp_key_iv = <<prefix::binary, bxor(3, byte), suffix::binary, 0::16>>
    rtcp_auth_iv = <<prefix::binary, bxor(4, byte), suffix::binary, 0::16>>
    rtcp_salt_iv = <<prefix::binary, bxor(5, byte), suffix::binary, 0::16>>

    cipher_key = aes_128_ctr_encrypt(master_key, <<master_salt::binary, 0::16>>, 128)
    auth_key = aes_128_ctr_encrypt(master_key, auth_iv, 160)
    cipher_salt = aes_128_ctr_encrypt(master_key, salt_iv, 112)
    rtcp_cipher_key = aes_128_ctr_encrypt(master_key, rtcp_key_iv, 128)
    rtcp_auth_key = aes_128_ctr_encrypt(master_key, rtcp_auth_iv, 160)
    rtcp_salt_key = aes_128_ctr_encrypt(master_key, rtcp_salt_iv, 112)

    {cipher_key, auth_key, cipher_salt, rtcp_cipher_key, rtcp_auth_key, rtcp_salt_key}
  end

  defp aes_128_ctr_encrypt(key, iv, input_size) do
    :crypto.crypto_one_time(:aes_128_ctr, key, iv, <<0::size(input_size)>>, encrypt: true)
  end

  defp get_ctx(%{contexts: contexts}, ssrc) when is_map_key(contexts, ssrc) do
    contexts[ssrc]
  end

  defp get_ctx(session, ssrc) do
    base_iv =
      <<session.rtp_salt::binary, 0::16>>
      |> :crypto.exor(<<ssrc::64, 0::64>>)
      |> :crypto.bytes_to_integer()

    rtcp_base_iv =
      <<session.rtcp_salt::binary, 0::16>>
      |> :crypto.exor(<<ssrc::64, 0::64>>)
      |> :crypto.bytes_to_integer()

    %ExSRTP.Context{base_iv: base_iv, rtcp_base_iv: rtcp_base_iv}
  end

  defp maybe_inc_roc(%{last_seq: last_seq} = ctx, %{sequence_number: seq}) when seq < last_seq do
    %{ctx | roc: ctx.roc + 1, last_seq: seq}
  end

  defp maybe_inc_roc(ctx, %{sequence_number: seq}), do: %{ctx | last_seq: seq}
end
