defmodule ExSRTP.Context do
  @moduledoc false

  @type t :: %__MODULE__{
          roc: non_neg_integer(),
          base_iv: non_neg_integer(),
          last_seq: non_neg_integer()
        }

  defstruct [:base_iv, last_seq: 0, roc: 0]
end
