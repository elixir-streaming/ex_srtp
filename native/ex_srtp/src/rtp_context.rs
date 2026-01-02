use std::cmp::max;

#[derive(Default)]
pub(crate) struct RTPContext {
    roc: u32,
    last_seq: u16,
    s_l: Option<u16>,
}

pub(crate) struct RTCPContext {
    pub index: u32,
}

impl RTPContext {
    pub fn inc_roc(&mut self, seq: u16) -> u32 {
        if seq < self.last_seq {
            self.roc = self.roc.wrapping_add(1);
        }
        self.last_seq = seq;
        self.roc
    }

    pub fn estimate_roc(&self, seq_number: u16) -> u32 {
        let s_l = match self.s_l {
            Some(s_l) => s_l,
            None => {
                return self.roc;
            }
        };

        if s_l < 32_768 {
            if seq_number as i32 - s_l as i32 > 32_768 {
                return self.roc.wrapping_sub(1);
            } else {
                return self.roc;
            }
        } else {
            if s_l as i32 - 32_768 > seq_number as i32 {
                return self.roc.wrapping_add(1);
            } else {
                return self.roc;
            }
        }
    }

    pub fn update_roc(&mut self, seq_number: u16) -> () {
        let s_l = match self.s_l {
            Some(s_l) => s_l,
            None => {
                self.s_l = Some(seq_number);
                return;
            }
        };

        if s_l < 32_768 {
            if seq_number as i32 - s_l as i32 <= 32_768 {
                self.s_l = Some(max(s_l, seq_number));
            }
        } else {
            if s_l as i32 - 32_768 > seq_number as i32 {
                self.roc = self.roc.wrapping_add(1);
                self.s_l = Some(seq_number);
            } else {
                self.s_l = Some(max(s_l, seq_number));
            }
        }
    }
}
