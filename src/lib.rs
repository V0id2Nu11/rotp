#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
use crypto::{hmac::Hmac, mac::Mac, sha1::Sha1};
use std::ops::{Deref, DerefMut};
use std::time::SystemTime;

#[derive(Default)]
struct BaseOtp<'a> {
    key: &'a str,
    factor: u64,
}

impl<'a> BaseOtp<'a> {
    // setter
    fn factor(&mut self, factor: u64) {
        self.factor = factor;
    }
}

trait GenOtp {
    fn hmac_sha1(&self) -> [u8; 20];
    fn dyn_trunc(&self) -> [u8; 4] {
        let hs = self.hmac_sha1();
        let offset: usize = (hs[19] & 0x0f_u8).into();
        let sbits: [u8; 4] = [
            hs[offset] & 0x7f_u8,
            hs[offset + 1],
            hs[offset + 2],
            hs[offset + 3],
        ];
        sbits
    }
    fn str2num(&self) -> u32 {
        let sbits = self.dyn_trunc();
        let mut result: u32 = 0x00_00_00_00_u32;
        result |= sbits[0] as u32;
        result = (result << 8) | (sbits[1] as u32);
        result = (result << 8) | (sbits[2] as u32);
        result = (result << 8) | (sbits[3] as u32);
        result
    }
    fn code(&self) -> u32 {
        let num = self.str2num();
        num % (10_u32.pow(6_u32))
    }
}

impl<'a> GenOtp for BaseOtp<'a> {
    fn hmac_sha1(&self) -> [u8; 20] {
        let mut hmac = Hmac::new(Sha1::new(), self.key.as_bytes());
        let data: [u8; 8] = [
            (0xff_00_00_00_00_00_00_00 & self.factor >> 56) as u8,
            (0x00_ff_00_00_00_00_00_00 & self.factor >> 48) as u8,
            (0x00_00_ff_00_00_00_00_00 & self.factor >> 40) as u8,
            (0x00_00_00_ff_00_00_00_00 & self.factor >> 32) as u8,
            (0x00_00_00_00_ff_00_00_00 & self.factor >> 24) as u8,
            (0x00_00_00_00_00_ff_00_00 & self.factor >> 16) as u8,
            (0x00_00_00_00_00_00_ff_00 & self.factor >> 8) as u8,
            (0x00_00_00_00_00_00_00_ff & self.factor) as u8,
        ];
        hmac.input(&data);
        let mut output: [u8; 20] = [0_u8; 20];
        hmac.raw_result(&mut output);
        output
    }
}

struct Hotp<'a>(BaseOtp<'a>);

impl<'a> Hotp<'a> {
    fn new() -> Self { Self(BaseOtp::default()) }
    fn key(&mut self, key: &'a str) -> &mut Self {
        self.0.key = key;
        self
    }
    fn factor(&mut self, factor: u64) -> &mut Self {
        self.0.factor = factor;
        self
    }
    fn hotp(&self) -> BaseOtp<'a> {
        BaseOtp { ..self.0 }
    }
}

struct Totp<'a>(BaseOtp<'a>);

impl<'a> Totp<'a> {
    fn new() -> Self { Self(BaseOtp::default()) }
    fn key(&mut self, key: &'a str) -> &mut Self {
        self.0.key = key;
        self
    }
    fn totp(&self) -> BaseOtp<'a> {
        BaseOtp { ..self.0 }
    }


#[cfg(test)]
mod tests {
    use super::*;
    const KEY: &str = "12345678901234567890";
    const HOTP_CODE_0: u32 = 755224;
    const HOTP_CODE_1: u32 = 287082;
    const HOTP_CODE_2: u32 = 359152;
    const HOTP_CODE_3: u32 = 969429;

    #[test]
    fn create_hotp() {
        let hotp = Hotp::new().key(KEY).factor(0).hotp();
        assert_eq!(hotp.code(), HOTP_CODE_0);
    }

    #[test]
    fn change_hotp() {
        let mut hotp = Hotp::new().key(KEY).factor(0).hotp();
        assert_eq!(hotp.code(), HOTP_CODE_0);
        hotp.factor(1);
        assert_eq!(hotp.code(), HOTP_CODE_1);
    }
}
