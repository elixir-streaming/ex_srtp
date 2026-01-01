defmodule ExSRTP.RTPContext do
  @moduledoc """
  SRTP RTP context state.
  """

  import Bitwise

  alias ExSRTP.ReplayList

  @compile {:inline, inc_roc: 2, estimate_roc: 2}

  @max_roc 1 <<< 32
  @default_replay_window 64

  @type t :: %__MODULE__{
          roc: non_neg_integer(),
          s_l: non_neg_integer() | nil,
          last_seq: non_neg_integer(),
          rtp_replay: ReplayProtection.t() | nil
        }

  defstruct [:s_l, :rtp_replay, last_seq: 0, roc: 0]

  @doc false
  @spec new() :: t()
  @spec new(non_neg_integer()) :: t()
  def new(replay_window_size \\ @default_replay_window) do
    %__MODULE__{
      rtp_replay: ReplayList.new(replay_window_size)
    }
  end

  @doc false
  @spec inc_roc(t(), non_neg_integer()) :: t()
  def inc_roc(%{last_seq: last_seq} = ctx, seq) when seq < last_seq do
    %{ctx | roc: rem(ctx.roc + 1, @max_roc), last_seq: seq}
  end

  def inc_roc(ctx, seq), do: %{ctx | last_seq: seq}

  # Get ROC at receiver side
  @doc false
  @spec estimate_roc(t(), non_neg_integer()) :: {non_neg_integer(), t()}
  def estimate_roc(%{s_l: nil} = ctx, seq_number) do
    {ctx.roc, %{ctx | s_l: seq_number}}
  end

  def estimate_roc(%{s_l: s_l} = ctx, seq_number) when s_l < 32_768 do
    cond do
      seq_number - s_l <= 32_768 -> {ctx.roc, %{ctx | s_l: max(s_l, seq_number)}}
      ctx.roc == 0 -> {@max_roc - 1, ctx}
      true -> {ctx.roc - 1, ctx}
    end
  end

  def estimate_roc(%{s_l: s_l} = ctx, seq_number) when s_l - 32_768 <= seq_number do
    {ctx.roc, %{ctx | s_l: max(s_l, seq_number)}}
  end

  def estimate_roc(ctx, seq_number) do
    roc = rem(ctx.roc + 1, @max_roc)
    {roc, %{ctx | roc: roc, s_l: seq_number}}
  end

  @doc false
  @spec check_replay(t(), non_neg_integer()) :: {:ok, t()} | {:error, :too_old | :replay}
  def check_replay(ctx, packet_index) do
    case ReplayList.check_and_update(ctx.rtp_replay, packet_index) do
      {:ok, new_replay} -> {:ok, %{ctx | rtp_replay: new_replay}}
      error -> error
    end
  end
end
