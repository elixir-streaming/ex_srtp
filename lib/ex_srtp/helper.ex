defmodule ExSRTP.Helper do
  @moduledoc false

  @compile {:inline, tag_size: 1}

  @spec rtcp_index(ExSRTP.Policy.profile(), binary()) :: {non_neg_integer(), non_neg_integer()}
  def rtcp_index(profile, <<_::32, ssrc::32, rest::binary>>) do
    tag_size = tag_size(profile)
    <<_::binary-size(byte_size(rest) - tag_size - 4), _e::1, index::31, _tag::binary>> = rest
    {ssrc, index}
  end

  @spec tag_size(ExSRTP.Policy.profile()) :: non_neg_integer()
  def tag_size(:aes_cm_128_hmac_sha1_80), do: 10
  def tag_size(:aes_cm_128_hmac_sha1_32), do: 4
end
