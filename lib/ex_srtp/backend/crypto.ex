defmodule ExSRTP.Backend.Crypto do
  @moduledoc """
  Implementation of `ExSRTP.Backend` using erlang `:crypto` module.
  """

  @behaviour ExSRTP.Backend

  import Bitwise

  alias ExRTCP.CompoundPacket
  alias ExSRTP.{Cipher, Helper, RTCPContext, RTPContext}

  @opaque t :: %__MODULE__{
            cipher: ExSRTP.Cipher.t() | nil,
            rtp_replay_window_size: non_neg_integer() | nil,
            rtcp_replay_window_size: non_neg_integer() | nil,
            out_rtp_contexts: %{non_neg_integer() => RTPContext.t()},
            in_rtp_contexts: %{non_neg_integer() => RTPContext.t()},
            out_rtcp_contexts: %{non_neg_integer() => RTCPContext.t()},
            in_rtcp_contexts: %{non_neg_integer() => RTCPContext.t()}
          }

  defstruct [
    :cipher,
    :rtp_replay_window_size,
    :rtcp_replay_window_size,
    out_rtp_contexts: %{},
    in_rtp_contexts: %{},
    out_rtcp_contexts: %{},
    in_rtcp_contexts: %{}
  ]

  @impl true
  def init(%ExSRTP.Policy{} = policy) do
    cipher =
      case policy.profile do
        :aes_gcm_128_16_auth ->
          Cipher.AesGcm.new(policy.profile, policy.master_key, policy.master_salt)

        profile ->
          Cipher.AesCmHmacSha1.new(profile, policy.master_key, policy.master_salt)
      end

    session = %__MODULE__{
      cipher: cipher,
      rtp_replay_window_size: policy.rtp_replay_window_size,
      rtcp_replay_window_size: policy.rtcp_replay_window_size
    }

    {:ok, session}
  end

  @impl true
  def protect(%{ssrc: ssrc} = packet, session) do
    ctx = :rtp_out |> get_ctx(session, packet.ssrc) |> RTPContext.inc_roc(packet.sequence_number)
    encrypted_packet = Cipher.encrypt_rtp(session.cipher, packet, ctx.roc)
    session = %{session | out_rtp_contexts: Map.put(session.out_rtp_contexts, ssrc, ctx)}
    {:ok, encrypted_packet, session}
  end

  @impl true
  def protect_rtcp(compound_packet, session) do
    # first rtcp packet must be SR or RR
    ssrc = List.first(compound_packet).ssrc
    ctx = get_ctx(:rtcp_out, session, ssrc)

    data = ExRTCP.CompoundPacket.encode(compound_packet)
    encrypted_data = Cipher.encrypt_rtcp(session.cipher, data, ctx.index)

    session = %{
      session
      | out_rtcp_contexts: Map.put(session.out_rtcp_contexts, ssrc, RTCPContext.inc_index(ctx))
    }

    {:ok, encrypted_data, session}
  end

  @impl true
  def unprotect(data, session) do
    with {:ok, packet} <- ExRTP.Packet.decode(data),
         ctx <- get_ctx(:rtp_in, session, packet.ssrc),
         {roc, ctx} <- RTPContext.estimate_roc(ctx, packet.sequence_number),
         index <- roc <<< 16 ||| packet.sequence_number,
         {:ok, ctx} <- RTPContext.check_replay(ctx, index),
         {:ok, decrypted_packet} <- Cipher.decrypt_rtp(session.cipher, data, packet, roc) do
      session = %{session | in_rtp_contexts: Map.put(session.in_rtp_contexts, packet.ssrc, ctx)}
      {:ok, decrypted_packet, session}
    end
  end

  @impl true
  def unprotect_rtcp(data, session) do
    tag_size = Cipher.tag_size(session.cipher)
    {ssrc, index} = Helper.rtcp_index(tag_size, data)
    ctx = get_ctx(:rtcp_in, session, ssrc)

    with {:ok, ctx} <- RTCPContext.check_replay(ctx, index),
         {:ok, decrypted_data} <- Cipher.decrypt_rtcp(session.cipher, data),
         {:ok, packets} <- CompoundPacket.decode(decrypted_data) do
      session = %{
        session
        | in_rtcp_contexts: Map.put(session.in_rtcp_contexts, ssrc, ctx)
      }

      {:ok, packets, session}
    end
  end

  @compile {:inline, get_ctx: 3}
  defp get_ctx(:rtp_out, %{out_rtp_contexts: contexts}, ssrc) when is_map_key(contexts, ssrc) do
    contexts[ssrc]
  end

  defp get_ctx(:rtp_in, %{in_rtp_contexts: contexts}, ssrc) when is_map_key(contexts, ssrc) do
    contexts[ssrc]
  end

  defp get_ctx(:rtcp_out, %{out_rtcp_contexts: contexts}, ssrc) when is_map_key(contexts, ssrc) do
    contexts[ssrc]
  end

  defp get_ctx(:rtcp_in, %{in_rtcp_contexts: contexts}, ssrc) when is_map_key(contexts, ssrc) do
    contexts[ssrc]
  end

  defp get_ctx(:rtp_out, _session, _ssrc), do: RTPContext.new()
  defp get_ctx(:rtcp_out, _session, _ssrc), do: RTCPContext.new()
  defp get_ctx(:rtp_in, session, _ssrc), do: RTPContext.new(session.rtp_replay_window_size)
  defp get_ctx(:rtcp_in, session, _ssrc), do: RTCPContext.new(session.rtcp_replay_window_size)

  defimpl Inspect do
    import Inspect.Algebra

    def inspect(%ExSRTP.Backend.Crypto{} = session, opts) do
      concat([
        "#ExSRTP.Backend.Crypto<",
        to_doc(
          %{
            cipher: session.cipher.__struct__,
            rtp_replay_window_size: session.rtp_replay_window_size,
            rtcp_replay_window_size: session.rtcp_replay_window_size
          },
          opts
        ),
        ">"
      ])
    end
  end
end
