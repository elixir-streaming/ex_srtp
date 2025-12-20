defmodule ExSRTP.Backend.RustCrypto.Native do
  @moduledoc false

  use Rustler, otp_app: :ex_srtp, crate: "rustcrypto_nif"

  def init(_policy), do: :erlang.nif_error(:nif_not_loaded)

  def protect(_session, _header, _payload), do: :erlang.nif_error(:nif_not_loaded)

  def protect_rtcp(_session, _data), do: :erlang.nif_error(:nif_not_loaded)
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

    Native.protect(
      session,
      binary_part(packet, 0, byte_size(packet) - payload_len),
      binary_part(packet, byte_size(packet) - payload_len, payload_len)
    )
  end

  @impl ExSRTP.Backend
  def protect_rtcp(packets, session) do
    {:ok, Native.protect_rtcp(session, CompoundPacket.encode(packets)), session}
  end
end
