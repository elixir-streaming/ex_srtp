defmodule ExSRTP.Backend do
  @moduledoc """
  The behaviour or SRTP backends.
  """

  @type state :: term()
  @type protect_return :: {:ok, iodata(), state()} | {:error, term()}

  @doc """
  Initializes the SRTP backend state based on the given policy.
  """
  @callback init(ExSRTP.Policy.t()) :: {:ok, state()} | {:error, term()}

  @doc """
  Protects an RTP packet, returning the protected binary and updated state.
  """
  @callback protect(ExRTP.Packet.t(), state()) :: protect_return

  @doc """
  Protects an RTCP compound packet, returning the protected binary and updated state.
  """
  @callback protect_rtcp([ExRTCP.Packet.packet()], state()) :: protect_return

  @doc """
  Unprotects a protected RTP packet, returning the unprotected packet and updated state.
  """
  @callback unprotect(binary(), state()) :: {:ok, ExRTP.Packet.t(), state()} | {:error, term()}

  @doc """
  Unprotects a protected RTCP compound packet, returning the unprotected packets and updated state.
  """
  @callback unprotect_rtcp(binary(), state()) ::
              {:ok, [ExRTCP.Packet.packet()], state()} | {:error, term()}

  @compile {:inline, backend: 0}
  @doc false
  def backend do
    case Process.get(:srtp_backend) do
      nil ->
        backend = Application.get_env(:ex_srtp, :backend, ExSRTP.Backend.Crypto)
        Process.put(:srtp_backend, backend)
        backend

      backend ->
        backend
    end
  end
end
