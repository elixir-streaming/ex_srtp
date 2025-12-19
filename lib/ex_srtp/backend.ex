defmodule ExSRTP.Backend do
  @moduledoc """
  The behaviour or SRTP backends.
  """

  @type state :: term()

  @doc """
  Initializes the SRTP backend state based on the given policy.
  """
  @callback init(ExSRTP.Policy.t()) :: state()

  @doc """
  Protects an RTP packet, returning the protected binary and updated state.
  """
  @callback protect(ExRTP.Packet.t(), state()) :: {binary(), state()}

  @doc """
  Protects an RTCP compound packet, returning the protected binary and updated state.
  """
  @callback protect_rtcp([ExRTCP.Packet.t()], state()) :: {binary(), state()}

  @doc """
  Unprotects a protected RTP packet, returning the unprotected packet and updated state.
  """
  @callback unprotect(binary(), state()) :: {:ok, ExRTP.Packet.t(), state()} | {:error, term()}
end
