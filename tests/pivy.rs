#![cfg(all(feature = "vpicc", feature = "pivy-tests"))]
#![allow(clippy::zombie_processes)]

mod card;

use card::*;

use cfg_if::cfg_if;
use expectrl::{spawn, Eof, Regex, WaitStatus};

use std::io::{self, Read, Write};
use std::ops::{Deref, DerefMut};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

pub struct CommandWrapper(pub Child);

impl Deref for CommandWrapper {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}

impl DerefMut for CommandWrapper {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl CommandWrapper {
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        self.0.wait()
    }
}

impl Drop for CommandWrapper {
    fn drop(&mut self) {
        self.0.wait().ok();
    }
}

const CARD: &str = env!("PIV_DANGEROUS_TEST_CARD_READER");

const EXPECT_TIMEOUT: Option<Duration> = Some(Duration::from_secs(30));

#[derive(Default)]
struct LogWriter(Vec<u8>);

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Drop for LogWriter {
    fn drop(&mut self) {
        io::stdout().write_all(&self.0).unwrap();
    }
}

#[test_log::test]
fn list() {
    let test = || {
        let mut logger = LogWriter(Vec::new());
        let p = spawn("pivy-tool list").unwrap();
        let mut p = expectrl::session::log(p, &mut logger).unwrap();
        p.set_expect_timeout(EXPECT_TIMEOUT);
        p.expect(Regex("card: [0-9A-Z]{8}")).unwrap();
        p.expect(format!("device: {CARD}")).unwrap();
        p.expect("chuid: ok").unwrap();
        p.expect(Regex("guid: [0-9A-Z]*")).unwrap();
        p.expect("algos: 3DES AES256 ECCP256 (null) (null)")
            .unwrap();
        p.expect(Eof).unwrap();
        assert_eq!(
            p.get_process().wait().unwrap(),
            WaitStatus::Exited(p.get_process().pid(), 0)
        );
    };
    cfg_if! {
        if #[cfg(not(feature = "dangerous-test-real-card"))]{
            with_vsc(WITH_UUID, test);
            with_vsc(WITHOUT_UUID, test);
        } else {
            with_lock_and_reset(test)
        }
    }
}

#[test_log::test]
fn generate() {
    let test = || {
        let mut p = spawn("pivy-tool -A 3des -K 010203040506070801020304050607080102030405060708 generate 9A -a eccp256 -P 123456").unwrap();
        p.set_expect_timeout(EXPECT_TIMEOUT);
        p.expect(Regex(
            "ecdsa-sha2-nistp256 (?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)? PIV_slot_9A@[A-F0-9]{20}",
        ))
        .unwrap();
        p.expect(Eof).unwrap();
        assert_eq!(
            p.get_process().wait().unwrap(),
            WaitStatus::Exited(p.get_process().pid(), 0)
        );

        let mut p = spawn("pivy-tool -A 3des -K 010203040506070801020304050607080102030405060708 generate 9A -a eccp384 -P 123456").unwrap();
        p.set_expect_timeout(EXPECT_TIMEOUT);
        p.expect(Regex(
            "ecdsa-sha2-nistp384 (?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)? PIV_slot_9A@[A-F0-9]{20}",
        ))
        .unwrap();
        p.expect(Eof).unwrap();
        assert_eq!(
            p.get_process().wait().unwrap(),
            WaitStatus::Exited(p.get_process().pid(), 0)
        );
    };
    cfg_if! {
        if #[cfg(not(feature = "dangerous-test-real-card"))]{
            with_vsc(WITH_UUID, test);
            with_vsc(WITHOUT_UUID, test);
        } else {
            with_lock_and_reset(test)
        }
    }
    #[cfg(feature = "rsa")]
    {
        let test = || {
            let mut p = spawn("pivy-tool -A 3des -K 010203040506070801020304050607080102030405060708 generate 9A -a rsa2048 -P 123456").unwrap();
            p.set_expect_timeout(EXPECT_TIMEOUT);
            p.expect(Regex(
            "ssh-rsa (?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)? PIV_slot_9A@[A-F0-9]{20}",
        ))
        .unwrap();
            p.expect(Eof).unwrap();
            assert_eq!(
                p.get_process().wait().unwrap(),
                WaitStatus::Exited(p.get_process().pid(), 0)
            );
        };
        cfg_if! {
            if #[cfg(not(feature = "dangerous-test-real-card"))]{
                with_vsc(WITH_UUID, test);
                with_vsc(WITHOUT_UUID, test);
            } else {
            with_lock_and_reset(test)
            }
        }
    }
}

fn ecdh_inner(key: &str, requires_pin: bool) {
    let test = || {
        let mut p = spawn(format!("pivy-tool -A 3des -K 010203040506070801020304050607080102030405060708 generate {key} -a eccp256 -P 123456")).unwrap();
        p.set_expect_timeout(EXPECT_TIMEOUT);
        p.expect(Regex(&format!(
            "{}{key}{}",
            "ecdsa-sha2-nistp256 (?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)? PIV_slot_",
            "@[A-F0-9]{20}",
        )))
        .unwrap();
        p.expect(Eof).unwrap();
        assert_eq!(
            p.get_process().wait().unwrap(),
            WaitStatus::Exited(p.get_process().pid(), 0)
        );

        let mut p = CommandWrapper(
            Command::new("pivy-tool")
                .args(if requires_pin {
                    vec!["sign", key, "-P", "123456"]
                } else {
                    vec!["sign", key]
                })
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut stdin = p.stdin.take().unwrap();
        write!(stdin,
            "ecdsa-sha2-nistp256 \
                AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIK+WUxBiBEwHgT4ykw3FDC1kRRMZCQo2+iM9+8WQgz7eFhEcU78eVweIrqG0nyJaZeWhgcYTSDP+VisDftiQgo= \
                PIV_slot_9A@6E9BCA45D8AF4B9D95AA2E8C8C23BA49"        ).unwrap();
        drop(stdin);

        assert_eq!(p.wait().unwrap().code(), Some(0));
    };
    cfg_if! {
        if #[cfg(not(feature = "dangerous-test-real-card"))]{
            with_vsc(WITH_UUID, test);
            with_vsc(WITHOUT_UUID, test);
        } else {
            with_lock_and_reset(test)
        }
    }

    let test = || {
        let mut p = spawn(format!("pivy-tool -A 3des -K 010203040506070801020304050607080102030405060708 generate {key} -a eccp384 -P 123456")).unwrap();
        p.set_expect_timeout(EXPECT_TIMEOUT);
        p.expect(Regex(&format!(
            "{}{key}{}",
            "ecdsa-sha2-nistp384 (?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)? PIV_slot_",
            "@[A-F0-9]{20}",
        )))
        .unwrap();
        p.expect(Eof).unwrap();
        assert_eq!(
            p.get_process().wait().unwrap(),
            WaitStatus::Exited(p.get_process().pid(), 0)
        );

        let mut p = Command::new("pivy-tool")
            .args(if requires_pin {
                vec!["sign", key, "-P", "123456"]
            } else {
                vec!["sign", key]
            })
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = p.stdin.take().unwrap();
        write!(stdin,
            "ecdsa-sha2-nistp384 \
                AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIK+WUxBiBEwHgT4ykw3FDC1kRRMZCQo2+iM9+8WQgz7eFhEcU78eVweIrqG0nyJaZeWhgcYTSDP+VisDftiQgo= \
                PIV_slot_9A@6E9BCA45D8AF4B9D95AA2E8C8C23BA49"        ).unwrap();
        drop(stdin);

        assert_eq!(p.wait().unwrap().code(), Some(0));
    };
    cfg_if! {
        if #[cfg(not(feature = "dangerous-test-real-card"))]{
            with_vsc(WITH_UUID, test);
            with_vsc(WITHOUT_UUID, test);
        } else {
            with_lock_and_reset(test)
        }
    }
}

#[test_log::test]
fn ecdh_9a() {
    ecdh_inner("9A", true);
}
#[test_log::test]
fn ecdh_9d() {
    ecdh_inner("9D", true);
}
#[test_log::test]
fn ecdh_9e() {
    ecdh_inner("9E", false);
}

fn sign_inner(key: &str, requires_pin: bool) {
    #[cfg(feature = "rsa")]
    let test_rsa = || {
        let mut logger = LogWriter(Vec::new());
        let p = spawn(format!("pivy-tool -A 3des -K 010203040506070801020304050607080102030405060708 generate {key} -a rsa2048 -P 123456"))
            .unwrap();
        let mut p = expectrl::session::log(p, &mut logger).unwrap();
        p.set_expect_timeout(EXPECT_TIMEOUT);
        p.expect(Regex(&format!(
            "{}{key}{}",
            "ssh-rsa (?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)? PIV_slot_",
            "@[A-F0-9]{20}"
        )))
        .unwrap();
        p.expect(Eof).unwrap();
        assert_eq!(
            p.get_process().wait().unwrap(),
            WaitStatus::Exited(p.get_process().pid(), 0)
        );

        let mut p = CommandWrapper(
            Command::new("pivy-tool")
                .args(if requires_pin {
                    vec!["sign", key, "-P", "123456"]
                } else {
                    vec!["sign", key]
                })
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut stdin = p.stdin.take().unwrap();
        write!(stdin, "data").unwrap();
        drop(stdin);

        assert_eq!(p.wait().unwrap().code(), Some(0));
    };

    let test_p256 = || {
        let mut logger = LogWriter::default();
        let p = spawn(format!("pivy-tool -A 3des -K 010203040506070801020304050607080102030405060708 generate {key} -a eccp256 -P 123456"))
            .unwrap();
        let mut p = expectrl::session::log(p, &mut logger).unwrap();
        p.set_expect_timeout(EXPECT_TIMEOUT);
        p.expect(Regex(&format!("{}{key}{}","ecdsa-sha2-nistp256 (?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)? PIV_slot_", "@[A-F0-9]{20}"))).unwrap();
        p.expect(Eof).unwrap();
        assert_eq!(
            p.get_process().wait().unwrap(),
            WaitStatus::Exited(p.get_process().pid(), 0)
        );

        let mut p = CommandWrapper(
            Command::new("pivy-tool")
                .args(if requires_pin {
                    vec!["sign", key, "-P", "123456"]
                } else {
                    vec!["sign", key]
                })
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut stdin = p.stdin.take().unwrap();
        let mut stdout = p.stdout.take().unwrap();
        write!(stdin, "data").unwrap();
        drop(stdin);

        let mut out = Vec::new();
        stdout.read_to_end(&mut out).unwrap();
        println!("{out:02x?}");
        // Check that the signature is an asn.1 sequence
        let res: asn1::ParseResult<_> = asn1::parse(&out, |d| {
            d.read_element::<asn1::Sequence>()?.parse(|d| {
                d.read_element::<asn1::BigUint>()?;
                d.read_element::<asn1::BigUint>()?;
                Ok(())
            })
        });
        res.unwrap();

        assert_eq!(p.wait().unwrap().code(), Some(0));
    };

    let test = || {
        test_p256();
        #[cfg(feature = "rsa")]
        test_rsa();
    };

    cfg_if! {
        if #[cfg(not(feature = "dangerous-test-real-card"))]{
            with_vsc(WITH_UUID, test);
            with_vsc(WITHOUT_UUID, test);
        } else {
            with_lock_and_reset(test)
        }
    }
}

#[test_log::test]
fn sign_9a() {
    sign_inner("9A", true);
}
#[test_log::test]
fn sign_9d() {
    sign_inner("9D", true);
}
#[test_log::test]
fn sign_9e() {
    sign_inner("9E", false);
}

const LARGE_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIHNTCCBh2gAwIBAgIUBeJLVUnOULY3fhLvjaWOZe/qWfYwDQYJKoZIhvcNAQEL
BQAwggIoMQswCQYDVQQGEwJURTGBizCBiAYDVQQIDIGAVEVTVFRFU1RURVNUVEVT
VFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVT
VFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVT
VFRFU1RURVNUVEVTVFRFU1QxgYswgYgGA1UEBwyBgFRFU1RURVNUVEVTVFRFU1RU
RVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RU
RVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RU
RVNUVEVTVFRFU1RURVNUMUkwRwYDVQQKDEBURVNUVEVTVFRFU1RURVNUVEVTVFRF
U1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUMUkwRwYD
VQQLDEBURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVT
VFRFU1RURVNUVEVTVFRFU1RURVNUMUkwRwYDVQQDDEBURVNUVEVTVFRFU1RURVNU
VEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNU
MRwwGgYJKoZIhvcNAQkBFg10ZXN0QHRlc3QuY29tMB4XDTIzMDMzMDA5NDg0NFoX
DTI0MDMyOTA5NDg0NFowggIoMQswCQYDVQQGEwJURTGBizCBiAYDVQQIDIGAVEVT
VFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVT
VFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVT
VFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1QxgYswgYgGA1UEBwyBgFRFU1RU
RVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RU
RVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RU
RVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUMUkwRwYDVQQKDEBURVNUVEVTVFRF
U1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRF
U1RURVNUMUkwRwYDVQQLDEBURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVT
VFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUMUkwRwYDVQQDDEBURVNU
VEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNUVEVTVFRFU1RURVNU
VEVTVFRFU1RURVNUMRwwGgYJKoZIhvcNAQkBFg10ZXN0QHRlc3QuY29tMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjEZtjVvccB3j/ZZWdor3YDWou0Ww
JWc0A7bAaFKK2cWjY08atejeoeuOvqezAejhSgqA9R60B8LJSGFg6y3D3QJ3JOOx
8ZodYIl0/QNfIHG1oaG9hp7zCaGlqyV6J+Bn1Sm3A6ElrNjb6Hkc8+bqqfH7gZbW
w3vDgx6u3sgnB6QnP/Zg9+H/1Ws3rCEyU8eaJhQpi2JBzODLDGmVkoo07U4D/7TG
nu5LgPBIRV0vmiCejMtpYhPCGAnTSdbhvKkNJAkZ8s225YlLFACgTVVmpcGb+cKu
RVXxZXFI1sWeIz9RMflobkpemKxHSUtuQJxJMDbPyOPqwd5CRFHgs7tRBwIDAQAB
o1MwUTAdBgNVHQ4EFgQUfRto8fDPPLA/ok5lgK7MypPSh54wHwYDVR0jBBgwFoAU
fRto8fDPPLA/ok5lgK7MypPSh54wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAWyy0drsTRfU8/J+rrX4trDb9o6iy7dSHyrpxo/TbaxBFTH69OJGb
Q8YbutSq1a4m4UaSnGJYwarVCxmntjciz7byhfUwFEAdZ/rqwCeaqTdomGiYUisM
Dmf/WiLYxRCpxr8tkkc332OlmHeBsDHKYY0G6dpdiTAGrjGNQZJJQc1wzy/+guZE
UWr6jSVOel/u47jadbFK2/4a8ZnZEuEU0nn5h01lFY3fvrHr93Z3yzZ60LKeMszs
SmDyoVI1XfNSJd8YbshGP91CVHFnDWDqo1JWV7hRev5g3XJfobIAAAqbL/H92BCT
N4vF6RP8Ck9wj1OYq/w82MkgxOPleUju4Q==
-----END CERTIFICATE-----";

#[test_log::test]
fn large_cert() {
    let test = || {
        let mut p = CommandWrapper(
            Command::new("pivy-tool")
                .args(["write-cert", "9A"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut stdin = p.stdin.take().unwrap();
        stdin.write_all(LARGE_CERT.as_bytes()).unwrap();
        drop(stdin);
        assert_eq!(p.wait().unwrap().code(), Some(0));

        let mut p = Command::new("pivy-tool")
            .args(["cert", "9A"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = p.stdout.take().unwrap();
        let mut buf = String::new();
        stdout.read_to_string(&mut buf).unwrap();
        assert_eq!(buf.strip_suffix('\n').unwrap(), LARGE_CERT);
        assert_eq!(p.wait().unwrap().code(), Some(0));
    };
    cfg_if! {
        if #[cfg(not(feature = "dangerous-test-real-card"))]{
            with_vsc(WITH_UUID, test);
            with_vsc(WITHOUT_UUID, test);
        } else {
            with_lock_and_reset(test)
        }
    }
}

#[test_log::test]
fn bad_admin_key() {
    let test = || {
        let output = Command::new("pivy-tool")
            .args(["-A", "3des", "-K", "@tests/bad_admin_key", "generate", "9A"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
    };

    cfg_if! {
        if #[cfg(not(feature = "dangerous-test-real-card"))]{
            with_vsc(WITH_UUID, test);
            with_vsc(WITHOUT_UUID, test);
        } else {
            with_lock_and_reset(test)
        }
    }
}
