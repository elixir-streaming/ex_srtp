defmodule ExSRTP.Policy do
  @moduledoc """
  Module describing a policy of SRTP.

  An SRTP policy defines the cryptographic parameters used to protect
  RTP and RTCP packets, including the master key, master salt, encryption
  and authentication profiles, and replay protection settings.

  ## Fields

    - `master_key` (binary): The master key used for encryption and authentication.
      Must be 16 bytes long.

    - `master_salt` (binary | nil): The master salt used in key derivation.
      Must be 14 bytes long if provided. Defaults to a zeroed 96-bit salt if not specified.

    - `rtp_profile` (profile | nil): The SRTP profile for RTP packets.
      Can be either `:aes_cm_128_hmac_sha1_80` or `:aes_cm_128_hmac_sha1_32`.
      Defaults to `:aes_cm_128_hmac_sha1_80` if not specified.

    - `rtcp_profile` (profile | nil): The SRTP profile for RTCP packets.
      Can be either `:aes_cm_128_hmac_sha1_80` or `:aes_cm_128_hmac_sha1_32`.
      Defaults to the value of `rtp_profile` if not specified.

    - `rtp_replay_window_size` (non_neg_integer | nil): The size of the replay protection window for RTP packets.
      Defaults to 64 if not specified.

    - `rtcp_replay_window_size` (non_neg_integer | nil): The size of the replay protection window for RTCP packets.
      Defaults to 128 if not specified.
  """

  @profiles [:aes_cm_128_hmac_sha1_80, :aes_cm_128_hmac_sha1_32]

  @type profile :: :aes_cm_128_hmac_sha1_80 | :aes_cm_128_hmac_sha1_32

  @type t :: %__MODULE__{
          master_key: binary(),
          master_salt: binary() | nil,
          rtp_profile: profile() | nil,
          rtcp_profile: profile() | nil,
          rtp_replay_window_size: non_neg_integer() | nil,
          rtcp_replay_window_size: non_neg_integer() | nil
        }

  @enforce_keys [:master_key]
  defstruct @enforce_keys ++
              [
                :master_salt,
                :rtp_profile,
                :rtcp_profile,
                rtp_replay_window_size: 64,
                rtcp_replay_window_size: 128
              ]

  @doc false
  @spec new(key :: binary(), profile :: profile()) :: {:ok, t()} | {:error, term()}
  def new(key, profile) when profile in @profiles do
    with {:ok, master, salt} <- get_master_and_salt(profile, key) do
      %__MODULE__{
        master_key: master,
        master_salt: salt,
        rtp_profile: profile,
        rtcp_profile: profile
      }
    end
  end

  def new(_key, _profile), do: {:error, :invalid_profile}

  @doc false
  def set_defaults(%__MODULE__{} = policy) do
    rtp_profile = policy.rtp_profile || :aes_cm_128_hmac_sha1_80

    %{
      policy
      | master_salt: policy.master_salt || <<0::96>>,
        rtp_profile: rtp_profile,
        rtcp_profile: policy.rtcp_profile || rtp_profile
    }
  end

  @doc false
  def validate(%__MODULE__{master_key: key}) when byte_size(key) != 16 do
    {:error, :invalid_master_key_size}
  end

  def validate(%__MODULE__{master_salt: salt}) when byte_size(salt) != 14 do
    {:error, :invalid_master_salt_size}
  end

  def validate(%__MODULE__{rtp_profile: profile}) when profile not in @profiles do
    {:error, :invalid_rtp_profile}
  end

  def validate(%__MODULE__{rtcp_profile: profile}) when profile not in @profiles do
    {:error, :invalid_rtcp_profile}
  end

  def validate(_policy), do: :ok

  defp get_master_and_salt(_profile, key) do
    case byte_size(key) do
      30 -> {:ok, binary_part(key, 0, 16), binary_part(key, 16, 14)}
      16 -> {:ok, key, <<0::96>>}
      _ -> {:error, :invalid_key_size}
    end
  end
end
