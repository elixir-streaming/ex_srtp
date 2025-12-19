defmodule ExSRTP.Policy do
  @moduledoc """
  Module describing a policy of SRTP.
  """

  @type profile :: :aes_cm_128_hmac_sha1_80

  @type t :: %__MODULE__{
          master_key: binary(),
          master_salt: binary() | nil,
          rtp_profile: profile() | nil,
          rtcp_profile: profile() | nil
        }

  @enforce_keys [:master_key]
  defstruct @enforce_keys ++ [:master_salt, :rtp_profile, :rtcp_profile]

  @doc false
  def set_defaults(%__MODULE__{} = policy) do
    %{
      policy
      | master_salt: policy.master_salt || <<0::96>>,
        rtp_profile: policy.rtp_profile || :aes_cm_128_hmac_sha1_80,
        rtcp_profile: policy.rtcp_profile || :aes_cm_128_hmac_sha1_80
    }
  end
end
