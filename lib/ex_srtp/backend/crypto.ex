defmodule ExSRTP.Backend.Crypto do
  @moduledoc """
  Implementation of `ExSRTP.Backend` using erlang `:crypto` module.
  """

  @behaviour ExSRTP.Backend

  import Bitwise

  alias ExRTCP.CompoundPacket
  alias ExSRTP.{RTCPContext, RTPContext}

  @rtp_session_key_label 0
  @rtp_auth_key_label 1
  @rtp_salt_label 2
  @rtcp_session_key_label 3
  @rtcp_auth_key_label 4
  @rtcp_salt_label 5

  @type t :: %__MODULE__{
          rtp_profile: ExSRTP.Policy.profile(),
          rtcp_profile: ExSRTP.Policy.profile(),
          rtp_session_key: binary() | nil,
          rtp_auth_key: binary() | nil,
          rtp_salt: binary() | nil,
          rtcp_session_key: binary() | nil,
          rtcp_auth_key: binary() | nil,
          rtcp_salt: binary() | nil,
          out_rtp_contexts: %{non_neg_integer() => RTPContext.t()},
          in_rtp_contexts: %{non_neg_integer() => RTPContext.t()},
          out_rtcp_contexts: %{non_neg_integer() => Context.t()},
          in_rtcp_contexts: %{non_neg_integer() => Context.t()}
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
    out_rtp_contexts: %{},
    in_rtp_contexts: %{},
    out_rtcp_contexts: %{},
    in_rtcp_contexts: %{}
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
    |> then(&{:ok, &1})
  end

  @impl true
  def protect(%{ssrc: ssrc} = packet, session) do
    ctx = session |> get_rtp_out_ctx(packet.ssrc) |> RTPContext.inc_roc(packet.sequence_number)

    idx = ctx.roc <<< 16 ||| packet.sequence_number
    iv = bxor(ctx.base_iv, idx <<< 16)

    header = ExRTP.Packet.encode(%{packet | payload: <<>>})

    packet = do_protect(session, header, packet.payload, iv, ctx.roc)
    session = %{session | out_rtp_contexts: Map.put(session.out_rtp_contexts, ssrc, ctx)}
    {:ok, packet, session}
  end

  @impl true
  def protect_rtcp(compound_packet, session) do
    # first rtcp packet must be SR or RR
    ssrc = List.first(compound_packet).ssrc
    ctx = get_rtcp_out_ctx(session, ssrc)
    data = ExRTCP.CompoundPacket.encode(compound_packet)

    iv = bxor(ctx.base_iv, ctx.index <<< 16)
    data = do_protect_rtcp(session, data, iv, ctx.index)

    session = %{
      session
      | out_rtcp_contexts: Map.put(session.out_rtcp_contexts, ssrc, RTCPContext.inc_index(ctx))
    }

    {:ok, data, session}
  end

  @impl true
  def unprotect(data, session) do
    with {:ok, packet} <- ExRTP.Packet.decode(data),
         ctx <- get_rtp_in_ctx(session, packet.ssrc),
         {roc, ctx} <- RTPContext.estimate_roc(ctx, packet.sequence_number),
         index <- roc <<< 16 ||| packet.sequence_number,
         {:ok, ctx} <- RTPContext.check_replay(ctx, index),
         :ok <- authenticate(session, roc, data) do
      tag_size = tag_size(session.rtp_profile)

      <<encrypted_data::binary-size(byte_size(packet.payload) - tag_size), _tag::binary>> =
        packet.payload

      decrypted_data =
        :crypto.crypto_one_time(
          :aes_128_ctr,
          session.rtp_session_key,
          <<bxor(ctx.base_iv, index <<< 16)::128>>,
          encrypted_data,
          encrypt: false
        )

      {:ok, %{packet | payload: decrypted_data},
       %{
         session
         | in_rtp_contexts: Map.put(session.in_rtp_contexts, packet.ssrc, ctx)
       }}
    end
  end

  @impl true
  def unprotect_rtcp(<<header::32, ssrc::32, _::binary>> = data, session) do
    ctx = get_rtcp_in_ctx(session, ssrc)

    with {:ok, encrypted_data, e, index} <- authenticate_rtcp(session, data),
         payload <- do_unprotect_rtcp(session, e, index, ctx.base_iv, encrypted_data),
         {:ok, packets} <- CompoundPacket.decode(<<header::32, ssrc::32, payload::binary>>) do
      {:ok, packets, session}
    end
  end

  defp derive_rtp_keys(session, %{master_key: key, master_salt: salt}) do
    %{
      session
      | rtp_session_key: derive_key(key, salt, @rtp_session_key_label, 128),
        rtp_auth_key: derive_key(key, salt, @rtp_auth_key_label, 160),
        rtp_salt: derive_key(key, salt, @rtp_salt_label, 112)
    }
  end

  defp derive_rtcp_keys(session, %{master_key: key, master_salt: salt}) do
    %{
      session
      | rtcp_session_key: derive_key(key, salt, @rtcp_session_key_label, 128),
        rtcp_auth_key: derive_key(key, salt, @rtcp_auth_key_label, 160),
        rtcp_salt: derive_key(key, salt, @rtcp_salt_label, 112)
    }
  end

  defp derive_key(key, salt, label, size) do
    <<prefix::binary-size(7), byte::8, suffix::binary-size(6)>> = salt
    iv = <<prefix::binary, bxor(label, byte), suffix::binary, 0::16>>
    :crypto.crypto_one_time(:aes_128_ctr, key, iv, <<0::size(size)>>, encrypt: true)
  end

  defp get_rtp_out_ctx(%{out_rtp_contexts: contexts}, ssrc) when is_map_key(contexts, ssrc) do
    contexts[ssrc]
  end

  defp get_rtp_out_ctx(session, ssrc), do: RTPContext.new(ssrc, session.rtp_salt)

  defp get_rtcp_out_ctx(%{out_rtcp_contexts: contexts}, ssrc) when is_map_key(contexts, ssrc) do
    contexts[ssrc]
  end

  defp get_rtcp_out_ctx(session, ssrc), do: RTCPContext.new(ssrc, session.rtcp_salt)

  defp get_rtp_in_ctx(%{in_rtp_contexts: contexts}, ssrc) when is_map_key(contexts, ssrc) do
    contexts[ssrc]
  end

  defp get_rtp_in_ctx(session, ssrc), do: RTPContext.new(ssrc, session.rtp_salt)

  defp get_rtcp_in_ctx(%{in_rtcp_contexts: contexts}, ssrc) when is_map_key(contexts, ssrc) do
    contexts[ssrc]
  end

  defp get_rtcp_in_ctx(session, ssrc), do: RTCPContext.new(ssrc, session.rtcp_salt)

  defp do_protect(session, header, payload, iv, roc) do
    tag_size = tag_size(session.rtp_profile)

    payload =
      :crypto.crypto_one_time(:aes_128_ctr, session.rtp_session_key, <<iv::128>>, payload,
        encrypt: true
      )

    auth_tag =
      :crypto.macN(
        :hmac,
        :sha,
        session.rtp_auth_key,
        [header, payload, <<roc::32>>],
        tag_size
      )

    [header, payload, auth_tag]
  end

  defp do_protect_rtcp(session, data, iv, rtcp_idx) do
    <<header::binary-size(8), payload::binary>> = data

    payload =
      :crypto.crypto_one_time(:aes_128_ctr, session.rtcp_session_key, <<iv::128>>, payload,
        encrypt: true
      )

    rtcp_packet = <<header::binary, payload::binary, 1::1, rtcp_idx::31>>
    tag_size = tag_size(session.rtcp_profile)
    auth_tag = :crypto.macN(:hmac, :sha, session.rtcp_auth_key, rtcp_packet, tag_size)
    <<rtcp_packet::binary, auth_tag::binary>>
  end

  defp authenticate(session, roc, data) do
    tag_size = tag_size(session.rtp_profile)
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
    tag_size = tag_size(session.rtcp_profile)

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

  defp tag_size(:aes_cm_128_hmac_sha1_80), do: 10
  defp tag_size(:aes_cm_128_hmac_sha1_32), do: 4

  defimpl Inspect do
    import Inspect.Algebra

    def inspect(%ExSRTP.Backend.Crypto{} = session, _opts) do
      concat([
        "#ExSRTP.Backend.Crypto<",
        "rtp_profile: #{inspect(session.rtp_profile)}, ",
        "rtcp_profile: #{inspect(session.rtcp_profile)}, ",
        ">"
      ])
    end
  end
end
