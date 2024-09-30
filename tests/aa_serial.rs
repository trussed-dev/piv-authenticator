#![cfg(feature = "dangerous-test-real-card")]
//! Test the serial number to ensure that tests run on the correct card

use expectrl::{spawn, Eof};

const CARD: &str = env!("PIV_DANGEROUS_TEST_CARD_READER");
const SERIAL: &str = env!("PIV_DANGEROUS_TEST_CARD_PIV_SERIAL");

#[test]
fn test_serial_number() {
    let mut p = spawn("piv-tool --serial").unwrap();
    p.expect(&format!("Using reader with a card: {CARD}"))
        .unwrap();
    p.expect(&format!("{SERIAL}")).unwrap();
    p.expect(Eof).unwrap();
}
