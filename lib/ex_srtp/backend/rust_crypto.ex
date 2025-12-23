defmodule ExSRTP.Backend.RustCrypto.Native do
  @moduledoc false

  use Rustler, otp_app: :ex_srtp, crate: "rustcrypto_nif"

  def init(_policy), do: :erlang.nif_error(:nif_not_loaded)

  def protect(_session, _header, _payload), do: :erlang.nif_error(:nif_not_loaded)

  def protect_rtcp(_session, _data), do: :erlang.nif_error(:nif_not_loaded)

  def unprotect(_session, _header, _payload), do: :erlang.nif_error(:nif_not_loaded)

  def unprotect_rtcp(_session, _data), do: :erlang.nif_error(:nif_not_loaded)

  def rtp_index(_session, _ssrc, _seq_number), do: :erlang.nif_error(:nif_not_loaded)
end

defmodule ExSRTP.Backend.RustCrypto do
  @moduledoc false

  @behaviour ExSRTP.Backend

  alias __MODULE__.Native
  alias ExRTCP.CompoundPacket
  alias ExSRTP.ReplayList

  @type t :: %__MODULE__{
          native: any(),
          rtcp_profile: ExSRTP.Policy.profile(),
          rtp_replay_window_size: non_neg_integer(),
          rtcp_replay_window_size: non_neg_integer(),
          rtp_replay_list: %{non_neg_integer() => ReplayList.t()},
          rtcp_replay_list: %{non_neg_integer() => ReplayList.t()}
        }

  defstruct [
    :native,
    :rtcp_profile,
    :rtp_replay_window_size,
    :rtcp_replay_window_size,
    rtp_replay_list: %{},
    rtcp_replay_list: %{}
  ]

  @impl ExSRTP.Backend
  def init(policy) do
    {:ok,
     %__MODULE__{
       native: Native.init(policy),
       rtcp_profile: policy.rtcp_profile,
       rtp_replay_window_size: policy.rtp_replay_window_size,
       rtcp_replay_window_size: policy.rtcp_replay_window_size
     }}
  end

  @impl ExSRTP.Backend
  def protect(packet, %{native: native} = session) do
    payload_len = byte_size(packet.payload)
    packet = ExRTP.Packet.encode(packet)

    encryped_data =
      Native.protect(
        native,
        binary_part(packet, 0, byte_size(packet) - payload_len),
        binary_part(packet, byte_size(packet) - payload_len, payload_len)
      )

    {:ok, encryped_data, session}
  end

  @impl ExSRTP.Backend
  def protect_rtcp(packets, %{native: native} = session) do
    {:ok, Native.protect_rtcp(native, CompoundPacket.encode(packets)), session}
  end

  @impl ExSRTP.Backend
  def unprotect(protected_packet, %{native: native} = session) do
    with {:ok, packet} <- ExRTP.Packet.decode(protected_packet),
         index <- Native.rtp_index(native, packet.ssrc, packet.sequence_number),
         replay_list <-
           session.rtp_replay_list[packet.ssrc] || ReplayList.new(session.rtp_replay_window_size),
         {:ok, replay_list} <- ReplayList.check_and_update(replay_list, index) do
      payload_len = byte_size(packet.payload)

      <<header::binary-size(byte_size(protected_packet) - payload_len), payload::binary>> =
        protected_packet

      case Native.unprotect(native, header, payload) do
        {:ok, unprotected_payload} ->
          session = %{
            session
            | rtp_replay_list: Map.put(session.rtp_replay_list, packet.ssrc, replay_list)
          }

          {:ok, %{packet | payload: unprotected_payload}, session}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  @impl ExSRTP.Backend
  def unprotect_rtcp(protected_packet, %{native: native} = session) do
    {ssrc, index} = ExSRTP.Helper.rtcp_index(session.rtcp_profile, protected_packet)

    replay_list =
      session.rtcp_replay_list[ssrc] || ReplayList.new(session.rtcp_replay_window_size)

    with {:ok, replay_list} <- ReplayList.check_and_update(replay_list, index),
         {:ok, unprotected_data} <- Native.unprotect_rtcp(native, protected_packet),
         {:ok, packets} <- CompoundPacket.decode(unprotected_data) do
      session = %{
        session
        | rtcp_replay_list: Map.put(session.rtcp_replay_list, ssrc, replay_list)
      }

      {:ok, packets, session}
    end
  end
end
