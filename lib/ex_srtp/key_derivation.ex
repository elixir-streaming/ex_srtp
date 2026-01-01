defmodule ExSRTP.KeyDerivation do
  @moduledoc false

  @spec aes_cm_derive(
          label :: integer(),
          master_key :: binary(),
          master_salt :: binary(),
          out_len :: non_neg_integer()
        ) :: binary()
  def aes_cm_derive(label, master_key, master_salt, out_len) do
    padding = byte_size(master_key) - byte_size(master_salt)
    <<prefix::binary-size(7), byte::8, suffix::binary>> = master_salt
    iv = <<prefix::binary, Bitwise.bxor(label, byte), suffix::binary, 0::size(padding * 8)>>
    :crypto.crypto_one_time(:aes_128_ctr, master_key, iv, <<0::size(out_len)>>, encrypt: true)
  end
end
