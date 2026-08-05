//! Test the serial number to ensure that tests run on the correct card

use expectrl::{spawn, Eof, Expect};

const CARD: &str = env!("PIV_DANGEROUS_TEST_CARD_READER");
const SERIAL: &str = env!("PIV_DANGEROUS_TEST_CARD_PIV_SERIAL");

mod card;

#[test]
fn test_serial_number() {
    if !card::dangerous_real_card_enabled() {
        return;
    }
    let mut p = spawn("piv-tool --serial").unwrap();
    p.expect(format!("Using reader with a card: {CARD}"))
        .unwrap();
    p.expect(SERIAL).unwrap();
    p.expect(Eof).unwrap();
}
