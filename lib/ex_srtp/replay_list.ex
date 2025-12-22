defmodule ExSRTP.ReplayList do
  @moduledoc false

  import Bitwise

  @type t :: %__MODULE__{
          window: non_neg_integer(),
          max: non_neg_integer() | nil,
          mask: non_neg_integer(),
          all_ones: non_neg_integer()
        }

  @enforce_keys [:window]
  defstruct [:window, :max, mask: 0, all_ones: 0]

  @spec new(window :: non_neg_integer()) :: t()
  def new(window) do
    %__MODULE__{window: window, all_ones: (1 <<< window) - 1}
  end

  @spec check_and_update(t(), non_neg_integer()) :: {:ok, t()} | {:error, :too_old | :replay}
  def check_and_update(%__MODULE__{max: nil} = st, idx) do
    {:ok, %__MODULE__{st | max: idx, mask: 1}}
  end

  def check_and_update(%__MODULE__{max: max} = st, idx) when idx > max do
    delta = idx - max
    new_mask = if delta >= st.window, do: 1, else: (st.mask <<< delta &&& st.all_ones) ||| 1
    {:ok, %__MODULE__{st | max: idx, mask: new_mask}}
  end

  def check_and_update(%__MODULE__{} = st, idx) do
    delta = st.max - idx

    cond do
      delta >= st.window ->
        {:error, :too_old}

      (st.mask &&& 1 <<< delta) != 0 ->
        {:error, :replay}

      true ->
        {:ok, %__MODULE__{st | mask: st.mask ||| 1 <<< delta}}
    end
  end
end
