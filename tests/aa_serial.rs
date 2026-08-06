//! Test the serial number to ensure that tests run on the correct card

use expectrl::{spawn, Eof, Expect};

const CARD: &str = env!("PIV_DANGEROUS_TEST_CARD_READER");
const SERIAL: &str = env!("PIV_DANGEROUS_TEST_CARD_PIV_SERIAL");

pub mod card;
use card::*;

#[test]
fn test_serial_number() {
    let test = || {
        let p = spawn("piv-tool --serial").unwrap();
        let mut logger = LogWriter(Vec::new());
        let mut p = expectrl::session::log(p, &mut logger).unwrap();
        p.expect(format!("Using reader with a card: {CARD}"))
            .unwrap();
        p.expect(SERIAL).unwrap();
        p.expect(Eof).unwrap();
    };
    if card::dangerous_real_card_enabled() {
        with_lock_and_reset(test)
    } else {
        with_vsc(WITHOUT_UUID, test);
    }
}
