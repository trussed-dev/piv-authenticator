mod setup;

use iso7816::Status::*;

// example: 00 47 00 9A 0B
//   AC 09
//      # P256
//      80 01 11
//      # 0xAA = Yubico extension (of course...), PinPolicy, 0x2 =
//      AA 01 02
//      # 0xAB = Yubico extension (of course...), TouchPolicy, 0x2 =
//      AB 01 02

#[test]
fn gen_keypair() {
    let cmd = cmd!("00 47 00 9A 0B  AC 09  80 01 11  AA 01 02  AB 01 02");

    // without PIN, no key generation
    setup::piv(|piv| {
        // not currently implemented
        //
        // let mut response = iso7816::Data::<16>::default();
        // assert_eq!(Err(SecurityStatusNotSatisfied), piv.respond(&cmd, &mut response));
    });
}
