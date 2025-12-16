defmodule ExSRTP.Context do
  @moduledoc """
  SRTP context state.
  """

  @type t :: %__MODULE__{
          roc: non_neg_integer(),
          base_iv: non_neg_integer(),
          rtcp_base_iv: non_neg_integer(),
          last_seq: non_neg_integer(),
          rtcp_idx: non_neg_integer()
        }

  defstruct [:base_iv, :rtcp_base_iv, last_seq: 0, roc: 0, rtcp_idx: 1]
end
