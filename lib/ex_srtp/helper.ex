defmodule ExSRTP.Helper do
  @moduledoc false

  @spec rtcp_index(integer(), binary()) :: {non_neg_integer(), non_neg_integer()}
  def rtcp_index(tag_size, <<_::32, ssrc::32, rest::binary>>) do
    <<_::binary-size(byte_size(rest) - tag_size - 4), _e::1, index::31, _tag::binary>> = rest
    {ssrc, index}
  end
end
