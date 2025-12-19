defmodule ExSRTP.Context do
  @moduledoc """
  SRTP context state.
  """

  import Bitwise

  @compile {:inline, inc_roc: 2, estimate_roc: 2}

  @srtp_index_max 1 <<< 31
  @max_roc 1 <<< 32

  @type t :: %__MODULE__{
          roc: non_neg_integer(),
          s_l: non_neg_integer() | nil,
          base_iv: non_neg_integer(),
          rtcp_base_iv: non_neg_integer(),
          last_seq: non_neg_integer(),
          rtcp_idx: non_neg_integer()
        }

  defstruct [:s_l, :base_iv, :rtcp_base_iv, last_seq: 0, roc: 0, rtcp_idx: 1]

  @doc false
  @spec new(non_neg_integer(), binary(), binary()) :: t()
  def new(ssrc, rtp_salt, rtcp_salt) do
    base_iv =
      <<rtp_salt::binary, 0::16>>
      |> :crypto.exor(<<ssrc::64, 0::64>>)
      |> :crypto.bytes_to_integer()

    rtcp_base_iv =
      <<rtcp_salt::binary, 0::16>>
      |> :crypto.exor(<<ssrc::64, 0::64>>)
      |> :crypto.bytes_to_integer()

    %__MODULE__{base_iv: base_iv, rtcp_base_iv: rtcp_base_iv}
  end

  @doc false
  @spec inc_roc(t(), non_neg_integer()) :: t()
  def inc_roc(%{last_seq: last_seq} = ctx, seq) when seq < last_seq do
    %{ctx | roc: rem(ctx.roc + 1, @max_roc), last_seq: seq}
  end

  def inc_roc(ctx, seq), do: %{ctx | last_seq: seq}

  @doc false
  @spec inc_rtcp_index(t()) :: t()
  def inc_rtcp_index(%{rtcp_idx: idx} = ctx) do
    %{ctx | rtcp_idx: rem(idx + 1, @srtp_index_max)}
  end

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
      true -> {ctx.roc, %{ctx | s_l: max(s_l, seq_number)}}
    end
  end

  def estimate_roc(%{s_l: s_l} = ctx, seq_number) when s_l - 32_768 <= seq_number do
    {ctx.roc, %{ctx | s_l: max(s_l, seq_number)}}
  end

  def estimate_roc(ctx, seq_number) do
    roc = rem(ctx.roc + 1, @max_roc)
    {roc, %{ctx | roc: roc, s_l: seq_number}}
  end
end
