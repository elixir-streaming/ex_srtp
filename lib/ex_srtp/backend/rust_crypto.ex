defmodule ExSRTP.Backend.RustCrypto.Native do
  @moduledoc false

  use Rustler, otp_app: :ex_srtp, crate: "rustcrypto_nif"

  def init(_policy), do: :erlang.nif_error(:nif_not_loaded)

  def protect(_session, _header, _payload), do: :erlang.nif_error(:nif_not_loaded)

  def protect_rtcp(_session, _data), do: :erlang.nif_error(:nif_not_loaded)

  def unprotect(_session, _header, _payload), do: :erlang.nif_error(:nif_not_loaded)

  def unprotect_rtcp(_session, _data), do: :erlang.nif_error(:nif_not_loaded)
end

defmodule ExSRTP.Backend.RustCrypto do
  @moduledoc false

  @behaviour ExSRTP.Backend

  alias __MODULE__.Native
  alias ExRTCP.CompoundPacket

  @impl ExSRTP.Backend
  def init(policy) do
    {:ok, Native.init(policy)}
  end

  @impl ExSRTP.Backend
  def protect(packet, session) do
    payload_len = byte_size(packet.payload)
    packet = ExRTP.Packet.encode(packet)

    encryped_data =
      Native.protect(
        session,
        binary_part(packet, 0, byte_size(packet) - payload_len),
        binary_part(packet, byte_size(packet) - payload_len, payload_len)
      )

    {:ok, encryped_data, session}
  end

  @impl ExSRTP.Backend
  def protect_rtcp(packets, session) do
    {:ok, Native.protect_rtcp(session, CompoundPacket.encode(packets)), session}
  end

  @impl ExSRTP.Backend
  def unprotect(protected_packet, session) do
    with {:ok, packet} <- ExRTP.Packet.decode(protected_packet) do
      payload_len = byte_size(packet.payload)

      <<header::binary-size(byte_size(protected_packet) - payload_len), payload::binary>> =
        protected_packet

      case Native.unprotect(session, header, payload) do
        {:ok, unprotected_payload} ->
          {:ok, %{packet | payload: unprotected_payload}, session}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  @impl ExSRTP.Backend
  def unprotect_rtcp(protected_packet, session) do
    case Native.unprotect_rtcp(session, protected_packet) do
      {:ok, unprotected_data} ->
        case CompoundPacket.decode(unprotected_data) do
          {:ok, packets} -> {:ok, packets, session}
          {:error, reason} -> {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end
end
