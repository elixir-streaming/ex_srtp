defprotocol ExSRTP.Cipher do
  @type packet :: ExRTP.Packet.t()

  @spec encrypt_rtp(t(), packet(), roc :: non_neg_integer()) ::
          iodata()
  def encrypt_rtp(value, packet, roc)

  @spec decrypt_rtp(t(), data :: binary(), packet(), roc :: non_neg_integer()) ::
          {:ok, packet()} | {:error, :authentication_failed}
  def decrypt_rtp(value, data, packet, roc)

  @spec encrypt_rtcp(t(), data :: binary(), index :: non_neg_integer()) ::
          iodata()
  def encrypt_rtcp(value, data, index)

  @spec decrypt_rtcp(t(), data :: binary()) ::
          {:ok, binary()} | {:error, :authentication_failed}
  def decrypt_rtcp(value, data)

  @spec tag_size(t()) :: non_neg_integer()
  def tag_size(value)
end
