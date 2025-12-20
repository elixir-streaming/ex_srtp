defmodule ExSRTP.Backend.Crypto do
  @moduledoc """
  Implementation of `ExSRTP.Backend` using erlang `:crypto` module.
  """

  @behaviour ExSRTP.Backend

  import Bitwise

  alias ExRTCP.CompoundPacket
  alias ExSRTP.Context

  @type t :: %__MODULE__{
          rtp_profile: ExSRTP.Policy.profile(),
          rtcp_profile: ExSRTP.Policy.profile(),
          rtp_session_key: binary() | nil,
          rtp_auth_key: binary() | nil,
          rtp_salt: binary() | nil,
          rtcp_session_key: binary() | nil,
          rtcp_auth_key: binary() | nil,
          rtcp_salt: binary() | nil,
          out_contexts: %{non_neg_integer() => Context.t()},
          in_contexts: %{non_neg_integer() => Context.t()}
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
    out_contexts: %{},
    in_contexts: %{}
  ]

  @impl true
  def init(%ExSRTP.Policy{} = policy) do
    session = %__MODULE__{
      rtp_profile: policy.rtp_profile,
      rtcp_profile: policy.rtcp_profile
    }

    session
    |> derive_rtp_keys(policy)
    |> derive_rtcp_keys(policy)
  end

  @impl true
  def protect(%{ssrc: ssrc} = packet, session) do
    ctx = session |> get_out_ctx(packet.ssrc) |> Context.inc_roc(packet)

    idx = ctx.roc <<< 16 ||| packet.sequence_number
    iv = bxor(ctx.base_iv, idx <<< 16)

    header = ExRTP.Packet.encode(%{packet | payload: <<>>})

    packet = do_protect(session, header, packet.payload, iv, ctx.roc)
    {packet, %{session | out_contexts: Map.put(session.out_contexts, ssrc, ctx)}}
  end

  @impl true
  def protect_rtcp(compound_packet, session) do
    # first rtcp packet must be SR or RR
    ssrc = List.first(compound_packet).ssrc
    ctx = get_out_ctx(session, ssrc)
    data = ExRTCP.CompoundPacket.encode(compound_packet)

    iv = bxor(ctx.rtcp_base_iv, ctx.rtcp_idx <<< 16)
    data = do_protect_rtcp(session, data, iv, ctx.rtcp_idx)

    session = %{
      session
      | out_contexts: Map.put(session.out_contexts, ssrc, Context.inc_rtcp_index(ctx))
    }

    {data, session}
  end

  @impl true
  def unprotect(data, session) do
    with {:ok, packet} <- ExRTP.Packet.decode(data),
         ctx <- get_in_ctx(session, packet.ssrc),
         {roc, ctx} <- Context.estimate_roc(ctx, packet.sequence_number),
         :ok <- authenticate(session, roc, data) do
      <<encrypted_data::binary-size(byte_size(packet.payload) - 10), _tag::binary>> =
        packet.payload

      iv = bxor(ctx.base_iv, (roc <<< 16 ||| packet.sequence_number) <<< 16)

      decrypted_data =
        :crypto.crypto_one_time(
          :aes_128_ctr,
          session.rtp_session_key,
          <<iv::128>>,
          encrypted_data,
          encrypt: false
        )

      {:ok, %{packet | payload: decrypted_data},
       %{
         session
         | in_contexts: Map.put(session.in_contexts, packet.ssrc, ctx)
       }}
    end
  end

  @impl true
  def unprotect_rtcp(<<header::32, ssrc::32, _::binary>> = data, session) do
    ctx = get_in_ctx(session, ssrc)

    with {:ok, encrypted_data, e, index} <- authenticate_rtcp(session, data),
         payload <- do_unprotect_rtcp(session, e, index, ctx.rtcp_base_iv, encrypted_data),
         {:ok, packets} <- CompoundPacket.decode(<<header::32, ssrc::32, payload::binary>>) do
      {:ok, packets, session}
    end
  end

  defp derive_rtp_keys(session, %{master_key: key} = policy) do
    <<prefix::binary-size(7), byte::8, suffix::binary-size(6)>> = policy.master_salt

    auth_iv = <<prefix::binary, bxor(1, byte), suffix::binary, 0::16>>
    salt_iv = <<prefix::binary, bxor(2, byte), suffix::binary, 0::16>>

    {cipher_key, auth_key, salt} = key_sizes(policy.rtp_profile)

    cipher_key = aes_128_ctr_encrypt(key, <<policy.master_salt::binary, 0::16>>, cipher_key)
    auth_key = aes_128_ctr_encrypt(key, auth_iv, auth_key)
    cipher_salt = aes_128_ctr_encrypt(key, salt_iv, salt)

    %{session | rtp_session_key: cipher_key, rtp_auth_key: auth_key, rtp_salt: cipher_salt}
  end

  defp derive_rtcp_keys(session, %{master_key: key} = policy) do
    <<prefix::binary-size(7), byte::8, suffix::binary-size(6)>> = policy.master_salt

    rtcp_key_iv = <<prefix::binary, bxor(3, byte), suffix::binary, 0::16>>
    rtcp_auth_iv = <<prefix::binary, bxor(4, byte), suffix::binary, 0::16>>
    rtcp_salt_iv = <<prefix::binary, bxor(5, byte), suffix::binary, 0::16>>

    {cipher_key, auth_key, salt} = key_sizes(policy.rtcp_profile)

    rtcp_cipher_key = aes_128_ctr_encrypt(key, rtcp_key_iv, cipher_key)
    rtcp_auth_key = aes_128_ctr_encrypt(key, rtcp_auth_iv, auth_key)
    rtcp_salt_key = aes_128_ctr_encrypt(key, rtcp_salt_iv, salt)

    %{
      session
      | rtcp_session_key: rtcp_cipher_key,
        rtcp_auth_key: rtcp_auth_key,
        rtcp_salt: rtcp_salt_key
    }
  end

  defp aes_128_ctr_encrypt(key, iv, input_size) do
    :crypto.crypto_one_time(:aes_128_ctr, key, iv, <<0::size(input_size)>>, encrypt: true)
  end

  defp get_out_ctx(%{out_contexts: contexts}, ssrc) when is_map_key(contexts, ssrc) do
    contexts[ssrc]
  end

  defp get_out_ctx(session, ssrc) do
    Context.new(ssrc, session.rtp_salt, session.rtcp_salt)
  end

  defp get_in_ctx(%{in_contexts: contexts}, ssrc) when is_map_key(contexts, ssrc) do
    contexts[ssrc]
  end

  defp get_in_ctx(session, ssrc) do
    Context.new(ssrc, session.rtp_salt, session.rtcp_salt)
  end

  defp do_protect(%{rtp_profile: :aes_cm_128_hmac_sha1_80} = session, header, payload, iv, roc) do
    payload =
      :crypto.crypto_one_time(:aes_128_ctr, session.rtp_session_key, <<iv::128>>, payload,
        encrypt: true
      )

    auth_tag =
      :crypto.mac_init(:hmac, :sha, session.rtp_auth_key)
      |> :crypto.mac_update(header)
      |> :crypto.mac_update(payload)
      |> :crypto.mac_update(<<roc::32>>)
      |> :crypto.mac_finalN(10)

    <<header::binary, payload::binary, auth_tag::binary>>
  end

  defp do_protect_rtcp(%{rtcp_profile: :aes_cm_128_hmac_sha1_80} = session, data, iv, rtcp_idx) do
    <<header::binary-size(8), payload::binary>> = data

    payload =
      :crypto.crypto_one_time(:aes_128_ctr, session.rtcp_session_key, <<iv::128>>, payload,
        encrypt: true
      )

    rtcp_packet = <<header::binary, payload::binary, 1::1, rtcp_idx::31>>
    auth_tag = :crypto.macN(:hmac, :sha, session.rtcp_auth_key, rtcp_packet, 10)
    <<rtcp_packet::binary, auth_tag::binary>>
  end

  defp authenticate(%{rtp_profile: :aes_cm_128_hmac_sha1_80} = session, roc, data) do
    tag_size = 10
    <<encrypted_data::binary-size(byte_size(data) - tag_size), tag::binary>> = data

    new_tag =
      :crypto.macN(
        :hmac,
        :sha,
        session.rtp_auth_key,
        <<encrypted_data::binary, roc::32>>,
        tag_size
      )

    if tag == new_tag, do: :ok, else: {:error, :auth_failed}
  end

  defp authenticate_rtcp(session, data) do
    tag_size = 10

    <<rtcp_data::binary-size(byte_size(data) - tag_size - 4), e::1, index::31, tag::binary>> =
      data

    new_tag =
      :crypto.mac_init(:hmac, :sha, session.rtcp_auth_key)
      |> :crypto.mac_update(rtcp_data)
      |> :crypto.mac_update(<<e::1, index::31>>)
      |> :crypto.mac_finalN(tag_size)

    encrypted_data = binary_part(rtcp_data, 8, byte_size(rtcp_data) - 8)
    if tag == new_tag, do: {:ok, encrypted_data, e, index}, else: {:error, :auth_failed}
  end

  defp do_unprotect_rtcp(_session, 0, _index, _base_iv, data), do: data

  defp do_unprotect_rtcp(session, _e, index, base_iv, data) do
    iv = bxor(base_iv, index <<< 16)

    :crypto.crypto_one_time(
      :aes_128_ctr,
      session.rtcp_session_key,
      <<iv::128>>,
      data,
      encrypt: false
    )
  end

  defp key_sizes(:aes_cm_128_hmac_sha1_80), do: {128, 160, 112}
  defp key_sizes(_), do: raise("Unsupported SRTP profile")

  defimpl Inspect do
    import Inspect.Algebra

    def inspect(%ExSRTP.Backend.Crypto{} = session, _opts) do
      concat([
        "#ExSRTP.Backend.Crypto<",
        "rtp_profile: #{inspect(session.rtp_profile)}, ",
        "rtcp_profile: #{inspect(session.rtcp_profile)}, ",
        "out_contexts: #{map_size(session.out_contexts)} contexts",
        ">"
      ])
    end
  end
end
