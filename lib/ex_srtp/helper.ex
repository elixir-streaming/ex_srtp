defmodule ExSRTP.Helper do
  @moduledoc false

  @spec rtcp_index(integer(), binary()) ::
          {:ok, non_neg_integer(), non_neg_integer()} | {:error, :not_enough_data}
  def rtcp_index(tag_size, <<_::32, ssrc::32, rest::binary>>) do
    case rest do
      <<_::binary-size(byte_size(rest) - tag_size - 4), _e::1, index::31, _tag::binary>> ->
        {:ok, ssrc, index}

      _ ->
        {:error, :not_enough_data}
    end
  end
end
