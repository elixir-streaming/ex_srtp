defmodule ExSRTP do
  @moduledoc """
  Module implementing Secure Real-time Transport Protocol (SRTP) as per RFC 3711.
  """

  import Bitwise

  @srtp_index_max Bitwise.bsl(1, 31)

  @type profile :: :aes_cm_128_hmac_sha1_80

  @type t :: %__MODULE__{
          ssrc: non_neg_integer() | :any_inbound,
          rtp: profile(),
          rtcp: profile(),
          master_key: binary(),
          master_salt: binary(),
          rtp_session_key: binary() | nil,
          rtp_auth_key: binary() | nil,
          rtp_salt: binary() | nil,
          rtcp_session_key: binary() | nil,
          rtcp_auth_key: binary() | nil,
          rtcp_salt: binary() | nil,
          contexts: %{non_neg_integer() => ExSRTP.Context.t()}
        }

  @enforce_keys [:ssrc, :master_key, :master_salt]
  defstruct @enforce_keys ++
              [
                :rtp_session_key,
                :rtp_auth_key,
                :rtp_salt,
                :rtcp_session_key,
                :rtcp_auth_key,
                :rtcp_salt,
                rtp: :aes_cm_128_hmac_sha1_80,
                rtcp: :aes_cm_128_hmac_sha1_80,
                contexts: %{}
              ]

  @doc """
  Creates a new SRTP session.
  """
  @spec new(keyword()) :: t()
  def new(opts) do
    mod = struct(__MODULE__, opts)

    {cipher_key, auth_key, cipher_salt, rtcp_session_key, rtcp_auth_key, rtcp_salt_key} =
      derive_keys(mod.master_key, mod.master_salt)

    %__MODULE__{
      mod
      | rtp_session_key: cipher_key,
        rtp_auth_key: auth_key,
        rtp_salt: cipher_salt,
        rtcp_session_key: rtcp_session_key,
        rtcp_auth_key: rtcp_auth_key,
        rtcp_salt: rtcp_salt_key
    }
  end

  @doc """
  Protects (encrypts and authenticates) an RTP packet.
  """
  @spec protect(t(), ExRTP.Packet.t()) :: {binary(), t()}
  def protect(srtp, %{ssrc: ssrc} = packet) do
    ctx = srtp |> get_ctx(packet.ssrc) |> maybe_inc_roc(packet)

    idx = ctx.roc <<< 16 ||| packet.sequence_number
    iv = bxor(ctx.base_iv, idx <<< 16)

    payload =
      :crypto.crypto_one_time(:aes_128_ctr, srtp.rtp_session_key, <<iv::128>>, packet.payload,
        encrypt: true
      )

    packet = ExRTP.Packet.encode(%{packet | payload: payload})
    auth_tag = :crypto.macN(:hmac, :sha, srtp.rtp_auth_key, <<packet::binary, ctx.roc::32>>, 10)

    {<<packet::binary, auth_tag::binary>>, %{srtp | contexts: Map.put(srtp.contexts, ssrc, ctx)}}
  end

  @doc """
  Protects (encrypts and authenticates) RTCP packets.
  """
  @spec protect_rtcp(t(), [ExRTCP.Packet.packet()]) :: {binary(), t()}
  def protect_rtcp(srtp, compound_packet) when is_list(compound_packet) do
    # first rtcp packet must be SR or RR
    ssrc = List.first(compound_packet).ssrc
    ctx = get_ctx(srtp, ssrc)
    <<header::binary-size(8), payload::binary>> = ExRTCP.CompoundPacket.encode(compound_packet)

    payload =
      :crypto.crypto_one_time(
        :aes_128_ctr,
        srtp.rtcp_session_key,
        <<bxor(ctx.rtcp_base_iv, ctx.rtcp_idx <<< 16)::128>>,
        payload,
        encrypt: true
      )

    rtcp_packet = <<header::binary, payload::binary, 1::1, ctx.rtcp_idx::31>>
    auth_tag = :crypto.macN(:hmac, :sha, srtp.rtcp_auth_key, rtcp_packet, 10)

    ctx = %{ctx | rtcp_idx: rem(ctx.rtcp_idx + 1, @srtp_index_max)}
    srtp = %{srtp | contexts: Map.put(srtp.contexts, ssrc, ctx)}

    {<<rtcp_packet::binary, auth_tag::binary>>, srtp}
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

  defp get_ctx(srtp, ssrc) do
    base_iv =
      <<srtp.rtp_salt::binary, 0::16>>
      |> :crypto.exor(<<ssrc::64, 0::64>>)
      |> :crypto.bytes_to_integer()

    rtcp_base_iv =
      <<srtp.rtcp_salt::binary, 0::16>>
      |> :crypto.exor(<<ssrc::64, 0::64>>)
      |> :crypto.bytes_to_integer()

    %ExSRTP.Context{base_iv: base_iv, rtcp_base_iv: rtcp_base_iv}
  end

  defp maybe_inc_roc(%{last_seq: last_seq} = ctx, %{sequence_number: seq}) when seq < last_seq do
    %{ctx | roc: ctx.roc + 1, last_seq: seq}
  end

  defp maybe_inc_roc(ctx, %{sequence_number: seq}), do: %{ctx | last_seq: seq}

  defimpl Inspect do
    import Inspect.Algebra

    def inspect(srtp, _opts) do
      concat([
        "#ExSRTP<ssrc: #{srtp.ssrc}",
        ", rtp: ",
        "#{srtp.rtp}",
        ", rtcp: ",
        "#{srtp.rtcp}",
        ">"
      ])
    end
  end
end
