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

  @doc """
  Unprotects (decrypts and verifies) an RTP packet.
  """
  @spec unprotect(binary(), t()) :: {:ok, ExRTP.Packet.t(), t()} | {:error, term()}
  def unprotect(data, srtp) do
    case Crypto.unprotect(data, srtp.session) do
      {:ok, packet, session} -> {:ok, packet, %{srtp | session: session}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Unprotects (decrypts and verifies) RTCP packets.
  """
  @spec unprotect_rtcp(binary(), t()) :: {:ok, [ExRTCP.Packet.packet()], t()} | {:error, term()}
  def unprotect_rtcp(data, srtp) do
    case Crypto.unprotect_rtcp(data, srtp.session) do
      {:ok, packets, session} -> {:ok, packets, %{srtp | session: session}}
      {:error, reason} -> {:error, reason}
    end
  end

  defimpl Inspect do
    import Inspect.Algebra

    def inspect(srtp, _opts) do
      concat(["#ExSRTP<session: ", to_doc(srtp.session, %Inspect.Opts{}), ">"])
    end
  end
end
