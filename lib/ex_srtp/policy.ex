defmodule ExSRTP.Policy do
  @moduledoc """
  Module describing a policy of SRTP.
  """

  @profiles [:aes_cm_128_hmac_sha1_80, :aes_cm_128_hmac_sha1_32]

  @type profile :: :aes_cm_128_hmac_sha1_80 | :aes_cm_128_hmac_sha1_32

  @type t :: %__MODULE__{
          master_key: binary(),
          master_salt: binary() | nil,
          rtp_profile: profile() | nil,
          rtcp_profile: profile() | nil
        }

  @enforce_keys [:master_key]
  defstruct @enforce_keys ++ [:master_salt, :rtp_profile, :rtcp_profile]

  @spec new(master_key :: binary(), master_salt :: binary()) :: t()
  def new(master_key, master_salt \\ <<0::96>>) do
    %__MODULE__{
      master_key: master_key,
      master_salt: master_salt
    }
  end

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
end
