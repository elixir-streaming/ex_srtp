defmodule ExSRTP do
  @moduledoc """
  Module implementing Secure Real-time Transport Protocol (SRTP) as per RFC 3711.
  """

  import ExSRTP.Backend, only: [backend: 0]

  alias ExSRTP.Policy

  @type t :: %__MODULE__{session: any()}

  defstruct [:session]

  @doc """
  Creates a new SRTP session.
  """
  @spec new(Policy.t()) :: {:ok, t()} | {:error, term()}
  def new(%Policy{} = policy) do
    policy = Policy.set_defaults(policy)

    with :ok <- Policy.validate(policy),
         {:ok, session} <- backend().init(policy) do
      {:ok, %__MODULE__{session: session}}
    end
  end

  @doc """
  Same as `new/1` but raises an error in case of failure.
  """
  @spec new!(Policy.t()) :: t()
  def new!(%Policy{} = policy) do
    case new(policy) do
      {:ok, srtp} -> srtp
      {:error, reason} -> raise "Failed to create SRTP session: #{inspect(reason)}"
    end
  end

  @doc """
  Protects (encrypts and authenticates) an RTP packet.
  """
  @spec protect(ExRTP.Packet.t(), t()) :: ExSRTP.Backend.protect_return()
  def protect(packet, srtp) do
    case backend().protect(packet, srtp.session) do
      {:ok, protected_packet, session} ->
        {:ok, protected_packet, %{srtp | session: session}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Same as `protect/2` but raises an error in case of failure.
  """
  @spec protect!(ExRTP.Packet.t(), t()) :: {binary(), t()}
  def protect!(packet, srtp) do
    case protect(packet, srtp) do
      {:ok, protected_packet, srtp} -> {protected_packet, srtp}
      {:error, reason} -> raise "Failed to protect RTP packet: #{inspect(reason)}"
    end
  end

  @doc """
  Protects (encrypts and authenticates) RTCP packets.
  """
  @spec protect_rtcp([ExRTCP.Packet.packet()], t()) :: ExSRTP.Backend.protect_return()
  def protect_rtcp(compound_packet, srtp) when is_list(compound_packet) do
    case backend().protect_rtcp(compound_packet, srtp.session) do
      {:ok, protected_packet, session} ->
        {:ok, protected_packet, %{srtp | session: session}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Same as `protect_rtcp/2` but raises an error in case of failure.
  """
  @spec protect_rtcp!([ExRTCP.Packet.packet()], t()) :: {binary(), t()}
  def protect_rtcp!(compound_packet, srtp) when is_list(compound_packet) do
    case protect_rtcp(compound_packet, srtp) do
      {:ok, protected_packet, srtp} -> {protected_packet, srtp}
      {:error, reason} -> raise "Failed to protect RTCP packets: #{inspect(reason)}"
    end
  end

  @doc """
  Unprotects (decrypts and verifies) an RTP packet.
  """
  @spec unprotect(binary(), t()) :: {:ok, ExRTP.Packet.t(), t()} | {:error, term()}
  def unprotect(data, srtp) do
    case backend().unprotect(data, srtp.session) do
      {:ok, packet, session} -> {:ok, packet, %{srtp | session: session}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Same as `unprotect/2` but raises an error in case of failure.
  """
  @spec unprotect!(binary(), t()) :: {ExRTP.Packet.t(), t()}
  def unprotect!(data, srtp) do
    case unprotect(data, srtp) do
      {:ok, packet, srtp} -> {packet, srtp}
      {:error, reason} -> raise "Failed to unprotect RTP packet: #{inspect(reason)}"
    end
  end

  @doc """
  Unprotects (decrypts and verifies) RTCP packets.
  """
  @spec unprotect_rtcp(binary(), t()) :: {:ok, [ExRTCP.Packet.packet()], t()} | {:error, term()}
  def unprotect_rtcp(data, srtp) do
    case backend().unprotect_rtcp(data, srtp.session) do
      {:ok, packets, session} -> {:ok, packets, %{srtp | session: session}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Same as `unprotect_rtcp/2` but raises an error in case of failure
  """
  @spec unprotect_rtcp!(binary(), t()) :: {[ExRTCP.Packet.packet()], t()}
  def unprotect_rtcp!(data, srtp) do
    case unprotect_rtcp(data, srtp) do
      {:ok, packets, srtp} -> {packets, srtp}
      {:error, reason} -> raise "Failed to unprotect RTCP packets: #{inspect(reason)}"
    end
  end

  defimpl Inspect do
    import Inspect.Algebra

    def inspect(srtp, _opts) do
      concat(["#ExSRTP<session: ", to_doc(srtp.session, %Inspect.Opts{}), ">"])
    end
  end
end
