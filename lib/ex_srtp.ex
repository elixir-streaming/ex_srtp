defmodule ExSRTP do
  @moduledoc """
  Module implementing Secure Real-time Transport Protocol (SRTP) as per RFC 3711.
  """

  alias ExSRTP.Backend.Crypto
  alias ExSRTP.Policy

  @type t :: %__MODULE__{session: any()}

  defstruct [:session]

  @doc """
  Creates a new SRTP session.
  """
  @spec new(Policy.t()) :: t()
  def new(%Policy{} = policy) do
    %__MODULE__{session: Crypto.init(Policy.set_defaults(policy))}
  end

  @doc """
  Protects (encrypts and authenticates) an RTP packet.
  """
  @spec protect(ExRTP.Packet.t(), t()) :: {:ok, binary(), t()} | {:error, term()}
  def protect(packet, srtp) do
    {protected_packet, session} = Crypto.protect(packet, srtp.session)
    {protected_packet, %{srtp | session: session}}
  end

  @doc """
  Protects (encrypts and authenticates) RTCP packets.
  """
  @spec protect_rtcp([ExRTCP.Packet.packet()], t()) :: {binary(), t()}
  def protect_rtcp(compound_packet, srtp) when is_list(compound_packet) do
    {protected_packet, session} = Crypto.protect_rtcp(compound_packet, srtp.session)
    {protected_packet, %{srtp | session: session}}
  end

  # defimpl Inspect do
  #   import Inspect.Algebra

  #   def inspect(srtp, _opts) do
  #     concat([
  #       "#ExSRTP<ssrc: #{srtp.ssrc}",
  #       ", rtp: ",
  #       "#{srtp.rtp}",
  #       ", rtcp: ",
  #       "#{srtp.rtcp}",
  #       ">"
  #     ])
  #   end
  # end
end
