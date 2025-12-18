defmodule ExSRTP.Policy do
  @moduledoc """
  Module describing a policy of SRTP.
  """

  @type profile :: :aes_cm_128_hmac_sha1_80

  @type t :: %__MODULE__{
          master_key: binary(),
          master_salt: binary(),
          rtp_profile: profile() | nil,
          rtcp_profile: profile() | nil
        }

  @enforce_keys [:master_key, :master_salt]
  defstruct @enforce_keys ++ [:rtp_profile, :rtcp_profile]
end
