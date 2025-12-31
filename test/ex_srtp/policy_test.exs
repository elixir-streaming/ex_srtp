defmodule ExSRTP.PolicyTest do
  use ExUnit.Case, async: true

  alias ExSRTP.Policy

  test "set_defaults/1 sets default values" do
    policy = %Policy{master_key: "mysecretkey12345"}
    updated_policy = Policy.set_defaults(policy)
    assert updated_policy.master_salt == <<0::112>>
    assert updated_policy.rtp_profile == :aes_cm_128_hmac_sha1_80
    assert updated_policy.rtcp_profile == :aes_cm_128_hmac_sha1_80
  end

  describe "validate/1" do
    test "returns error for invalid master key size" do
      policy = %Policy{master_key: "shortkey"}
      assert Policy.validate(policy) == {:error, :invalid_master_key_size}
    end

    test "returns error for invalid master salt size" do
      policy = %Policy{master_key: "mysecretkey12345", master_salt: "shortsalt"}
      assert Policy.validate(policy) == {:error, :invalid_master_salt_size}
    end

    test "returns error for invalid rtp profile" do
      policy = %Policy{master_key: "mysecretkey12345", rtp_profile: :invalid_profile}
      assert Policy.validate(policy) == {:error, :invalid_rtp_profile}
    end

    test "returns error for invalid rtcp profile" do
      policy = %Policy{
        master_key: "mysecretkey12345",
        rtp_profile: :aes_cm_128_hmac_sha1_80,
        rtcp_profile: :invalid_profile
      }

      assert Policy.validate(policy) == {:error, :invalid_rtcp_profile}
    end
  end
end
