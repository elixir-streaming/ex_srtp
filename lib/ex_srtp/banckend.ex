defmodule ExSRTP.Backend do
  @moduledoc """
  The behaviour or SRTP backends.
  """

  @type state :: term()

  @callback init(ExSRTP.Policy.t()) :: state()

  @callback protect(ExRTP.Packet.t(), state()) :: {binary(), state()}

  @callback protect_rtcp(ExRTCP.CompoundPacket.t(), state()) :: {binary(), state()}
end
