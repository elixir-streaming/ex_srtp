pub struct Context {
    pub roc: u32,
    pub base_iv: [u8; 16],
    pub rtcp_base_iv: [u8; 16],
    pub rtcp_index: u32,
    iv: [u8; 16],
    last_seq: u16,
    rtcp_iv: [u8; 16],
}

impl Context {
    pub fn new(ssrc: u32, rtp_salt: &[u8], rtcp_salt: &[u8]) -> Self {
        let mut base_iv = [0u8; 16];
        let mut rtcp_base_iv = [0u8; 16];
        let ssrc_bytes = ssrc.to_be_bytes();

        base_iv[0..14].copy_from_slice(rtp_salt);
        rtcp_base_iv[0..14].copy_from_slice(rtcp_salt);
        for i in 0..4 {
            base_iv[i + 4] ^= ssrc_bytes[i];
            rtcp_base_iv[i + 4] ^= ssrc_bytes[i];
        }

        Context {
            roc: 0,
            base_iv: base_iv,
            iv: [0u8; 16],
            last_seq: 0,
            rtcp_index: 1,
            rtcp_base_iv: rtcp_base_iv,
            rtcp_iv: [0u8; 16],
        }
    }

    pub fn inc_roc(&mut self, seq: u16) {
        if seq < self.last_seq {
            self.roc = self.roc.wrapping_add(1);
        }
        self.last_seq = seq;
    }

    pub fn iv(&mut self, header: &[u8]) -> &[u8; 16] {
        let bytes = self.roc.to_be_bytes();
        self.iv.copy_from_slice(&self.base_iv);

        for i in 0..4 {
            self.iv[i + 8] ^= bytes[i];
        }

        self.iv[12] ^= header[2];
        self.iv[13] ^= header[3];

        return &self.iv;
    }

    pub fn rtcp_iv(&mut self) -> &[u8; 16] {
        let bytes = self.rtcp_index.to_be_bytes();
        self.rtcp_iv.copy_from_slice(&self.rtcp_base_iv);

        for i in 0..4 {
            self.rtcp_iv[i + 10] ^= bytes[i];
        }

        return &self.rtcp_iv;
    }
}
