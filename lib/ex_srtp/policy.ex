defmodule ExSRTP.Policy do
  @moduledoc """
  Module describing a policy of SRTP.

  An SRTP policy defines the cryptographic parameters used to protect
  RTP and RTCP packets, including the master key, master salt, encryption
  and authentication profiles, and replay protection settings.

  ## Fields

    - `master_key` (binary): The master key used for encryption and authentication.
      Must be 16 bytes long.

    - `master_salt` (binary | nil): The master salt used in key derivation. Defaults to 0.

    - `profile` (profile | nil): The SRTP profile for RTP and RTCP packets.
      Defaults to `:aes_cm_128_hmac_sha1_80` if not specified.

    - `rtp_replay_window_size` (non_neg_integer | nil): The size of the replay protection window for RTP packets.
      Defaults to 64 if not specified.

    - `rtcp_replay_window_size` (non_neg_integer | nil): The size of the replay protection window for RTCP packets.
      Defaults to 128 if not specified.
  """

  @profiles [:aes_cm_128_hmac_sha1_80, :aes_cm_128_hmac_sha1_32, :aes_gcm_128_16_auth]

  @type profile :: :aes_cm_128_hmac_sha1_80 | :aes_cm_128_hmac_sha1_32 | :aes_gcm_128_16_auth
  @type master_key :: binary()
  @type master_salt :: binary()

  @type t :: %__MODULE__{
          master_key: master_key(),
          master_salt: master_salt() | nil,
          profile: profile() | nil,
          rtp_replay_window_size: non_neg_integer() | nil,
          rtcp_replay_window_size: non_neg_integer() | nil
        }

  @enforce_keys [:master_key]
  defstruct @enforce_keys ++
              [
                :master_salt,
                :profile,
                rtp_replay_window_size: 64,
                rtcp_replay_window_size: 128
              ]

  @doc """
  Relevant specification: https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml

      iex> ExSRTP.Policy.crypto_profile_from_dtls_srtp_protection_profile(0x01)
      {:ok, :aes_cm_128_hmac_sha1_80}

      iex> ExSRTP.Policy.crypto_profile_from_dtls_srtp_protection_profile(0x02)
      {:ok, :aes_cm_128_hmac_sha1_32}

      iex> ExSRTP.Policy.crypto_profile_from_dtls_srtp_protection_profile(0x03)
      {:error, :unsupported_crypto_profile}

      iex> ExSRTP.Policy.crypto_profile_from_dtls_srtp_protection_profile({0x00, 0x01})
      {:ok, :aes_cm_128_hmac_sha1_80}

      iex> ExSRTP.Policy.crypto_profile_from_dtls_srtp_protection_profile({0x00, 0x03})
      {:error, :unsupported_crypto_profile}
  """
  @spec crypto_profile_from_dtls_srtp_protection_profile(
          value :: pos_integer() | {pos_integer(), pos_integer()}
        ) :: {:ok, profile()} | {:error, :unsupported_crypto_profile}
  def crypto_profile_from_dtls_srtp_protection_profile(0x01), do: {:ok, :aes_cm_128_hmac_sha1_80}
  def crypto_profile_from_dtls_srtp_protection_profile(0x02), do: {:ok, :aes_cm_128_hmac_sha1_32}

  def crypto_profile_from_dtls_srtp_protection_profile(b) when is_number(b) do
    {:error, :unsupported_crypto_profile}
  end

  def crypto_profile_from_dtls_srtp_protection_profile({0x00, b}) when is_number(b) do
    crypto_profile_from_dtls_srtp_protection_profile(b)
  end

  def crypto_profile_from_dtls_srtp_protection_profile({a, b})
      when is_number(a) and is_number(b) do
    {:error, :unsupported_crypto_profile}
  end

  @doc false
  @spec new(key :: binary(), profile :: profile()) :: {:ok, t()} | {:error, term()}
  def new(key, profile) when profile in @profiles do
    with {:ok, master, salt} <- get_master_and_salt(profile, key) do
      {:ok,
       %__MODULE__{
         master_key: master,
         master_salt: salt,
         profile: profile
       }}
    end
  end

  def new(_key, _profile), do: {:error, :invalid_profile}

  @doc false
  def set_defaults(%__MODULE__{} = policy) do
    %{
      policy
      | master_salt: policy.master_salt || <<0::112>>,
        profile: policy.profile || :aes_cm_128_hmac_sha1_80
    }
  end

  @doc false
  def validate(%__MODULE__{master_key: key}) when byte_size(key) != 16 do
    {:error, :invalid_master_key_size}
  end

  # def validate(%__MODULE__{master_salt: salt}) when byte_size(salt) != 14 do
  #   {:error, :invalid_master_salt_size}
  # end

  def validate(%__MODULE__{profile: profile}) when profile not in @profiles do
    {:error, :invalid_profile}
  end

  def validate(_policy), do: :ok

  defp get_master_and_salt(profile, key) do
    {key_size, salt_size} =
      case profile do
        :aes_gcm_128_16_auth -> {16, 12}
        :aes_cm_128_hmac_sha1_80 -> {16, 14}
        :aes_cm_128_hmac_sha1_32 -> {16, 14}
      end

    cond do
      byte_size(key) == key_size + salt_size ->
        {:ok, binary_part(key, 0, key_size), binary_part(key, key_size, salt_size)}

      byte_size(key) == key_size ->
        {:ok, key, <<0::size(salt_size * 8)>>}

      true ->
        {:error, :invalid_key_size}
    end
  end
end
