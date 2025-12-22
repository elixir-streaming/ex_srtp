defmodule ExSRTP.RTCPContext do
  @moduledoc """
  SRTP context state.
  """

  import Bitwise

  alias ExSRTP.ReplayList

  @srtp_index_max 1 <<< 31
  @default_replay_window 64

  @type t :: %__MODULE__{
          base_iv: non_neg_integer(),
          index: non_neg_integer(),
          replay: ReplayProtection.t() | nil
        }

  defstruct [:base_iv, :replay, index: 1]

  @doc false
  @spec new(non_neg_integer(), binary()) :: t()
  def new(ssrc, salt, replay_window \\ @default_replay_window) do
    base_iv =
      <<salt::binary, 0::16>>
      |> :crypto.exor(<<ssrc::64, 0::64>>)
      |> :crypto.bytes_to_integer()

    %__MODULE__{
      base_iv: base_iv,
      replay: ReplayList.new(replay_window)
    }
  end

  @doc false
  @spec inc_index(t()) :: t()
  def inc_index(%{index: idx} = ctx) do
    %{ctx | index: rem(idx + 1, @srtp_index_max)}
  end

  @doc false
  @spec check_replay(t(), non_neg_integer()) :: {:ok, t()} | {:error, :replay | :tls_bloom_filter}
  def check_replay(ctx, packet_index) do
    case ReplayList.check_and_update(ctx.replay, packet_index) do
      {:ok, new_replay} -> {:ok, %{ctx | replay: new_replay}}
      error -> error
    end
  end
end
