defmodule ExSRTP.Context do
  @moduledoc """
  SRTP context state.
  """

  @srtp_index_max Bitwise.bsl(1, 31)

  @type t :: %__MODULE__{
          roc: non_neg_integer(),
          base_iv: non_neg_integer(),
          rtcp_base_iv: non_neg_integer(),
          last_seq: non_neg_integer(),
          rtcp_idx: non_neg_integer()
        }

  defstruct [:base_iv, :rtcp_base_iv, last_seq: 0, roc: 0, rtcp_idx: 1]

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

  @spec inc_roc(t(), non_neg_integer()) :: t()
  def inc_roc(%{last_seq: last_seq} = ctx, seq) when seq < last_seq do
    %{ctx | roc: ctx.roc + 1, last_seq: seq}
  end

  def inc_roc(ctx, seq), do: %{ctx | last_seq: seq}

  def inc_rtcp_index(%{rtcp_idx: idx} = ctx) do
    %{ctx | rtcp_idx: rem(idx + 1, @srtp_index_max)}
  end
end
