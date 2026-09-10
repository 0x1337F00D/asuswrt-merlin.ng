//! The command-line contract.
//!
//! `release/src/router/rc/usb.c:6045-6072` builds exactly this argument
//! vector and hands it to `_eval`:
//!
//! ```text
//! /usr/sbin/wsdd2 -d -w -i <lan_ifname> -b sku:<productid>,serial:<mac>
//! ```
//!
//! The option letters and their arguments are the vendor's getopt string
//! `"hd46utlwLWi:H:N:G:b:"` (`wsdd2.c:781`), reproduced letter for letter.
//! `-A` and `-B` are advertised by the vendor's own help text
//! (`wsdd2.c:723-724`) but are absent from that string, so the vendor rejects
//! them; this does too, rather than quietly widening the contract.

use crate::wsd::BootInfo;

/// Which address families to serve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Families {
    /// Serve IPv4.
    pub v4: bool,
    /// Serve IPv6.
    pub v6: bool,
}

/// Which transports to serve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transports {
    /// Serve UDP (multicast discovery and LLMNR).
    pub udp: bool,
    /// Serve TCP (the HTTP metadata endpoint).
    pub tcp: bool,
}

/// Which protocols to serve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Protocols {
    /// Serve LLMNR.
    pub llmnr: bool,
    /// Serve WS-Discovery.
    pub wsd: bool,
}

/// The parsed command line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Options {
    /// `-d`: fork into the background.
    pub daemon: bool,
    /// `-4` / `-6`; both when neither was given (`wsdd2.c:846`).
    pub families: Families,
    /// `-u` / `-t`; both when neither was given (`wsdd2.c:850`).
    pub transports: Transports,
    /// `-l` / `-w`; both when neither was given (`wsdd2.c:848`).
    pub protocols: Protocols,
    /// `-L`, the LLMNR debug level.
    pub llmnr_debug: u8,
    /// `-W`, the WS-Discovery debug level.
    pub wsd_debug: u8,
    /// `-i`; `None` for "any", which `-i any` and `-i ""` also select
    /// (`wsdd2.c:800`).
    pub interface: Option<String>,
    /// `-H`, overriding the host name.
    pub hostname: Option<String>,
    /// `-N`, overriding the NetBIOS name.
    pub netbios_name: Option<String>,
    /// `-G`, overriding the workgroup.
    pub workgroup: Option<String>,
    /// `-b` boot information, already merged over the defaults.
    pub boot: BootInfo,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            daemon: false,
            families: Families { v4: true, v6: true },
            transports: Transports {
                udp: true,
                tcp: true,
            },
            protocols: Protocols {
                llmnr: true,
                wsd: true,
            },
            llmnr_debug: 0,
            wsd_debug: 0,
            interface: None,
            hostname: None,
            netbios_name: None,
            workgroup: None,
            boot: BootInfo::default(),
        }
    }
}

/// What the parser decided.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Start with these options.
    Run(Box<Options>),
    /// `-h`: print the usage text and exit 0 (`wsdd2.c:706`).
    Help,
    /// `--self-test`: run the offline protocol self-test and exit.
    ///
    /// This is the only addition to the vendor contract.  It cannot collide
    /// with a vendor option: the vendor's getopt stops at the first `--`.
    SelfTest,
    /// Refuse to start, printing this reason.  The vendor called
    /// `help(prog, EXIT_FAILURE, ...)` for every one of these
    /// (`wsdd2.c:838-843`).
    Reject(String),
}

/// Longest value accepted for any string option.
///
/// `rc` passes a 15-byte interface name and a boot string built into a
/// 64-byte buffer (`rc/usb.c:6041`), so this is far above anything the
/// firmware sends and still bounds a hand-typed argument.
pub const MAX_OPTION_VALUE: usize = 256;

/// Parses the argument vector, `argv[0]` excluded.
#[must_use]
pub fn parse<I, S>(arguments: I) -> Outcome
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let arguments: Vec<String> = arguments
        .into_iter()
        .map(|value| value.as_ref().to_owned())
        .collect();
    if arguments.iter().any(|argument| argument == "--self-test") {
        if arguments.len() == 1 {
            return Outcome::SelfTest;
        }
        return Outcome::Reject(String::from("--self-test takes no other argument"));
    }

    let mut options = Options::default();
    let mut families = Families {
        v4: false,
        v6: false,
    };
    let mut transports = Transports {
        udp: false,
        tcp: false,
    };
    let mut protocols = Protocols {
        llmnr: false,
        wsd: false,
    };
    let mut index = 0_usize;
    while let Some(argument) = arguments.get(index) {
        index = index.saturating_add(1);
        let Some(letters) = argument.strip_prefix('-') else {
            return Outcome::Reject(format!("Unknown argument '{}'", sanitise(argument)));
        };
        if letters.is_empty() || argument.starts_with("--") {
            return Outcome::Reject(format!("Bad option '{}'", sanitise(argument)));
        }
        for (offset, letter) in letters.char_indices() {
            match letter {
                'h' => return Outcome::Help,
                'd' => options.daemon = true,
                '4' => families.v4 = true,
                '6' => families.v6 = true,
                'u' => transports.udp = true,
                't' => transports.tcp = true,
                'l' => protocols.llmnr = true,
                'w' => protocols.wsd = true,
                'L' => options.llmnr_debug = options.llmnr_debug.saturating_add(1),
                'W' => options.wsd_debug = options.wsd_debug.saturating_add(1),
                'i' | 'H' | 'N' | 'G' | 'b' => {
                    // getopt(3) allows both "-ibr0" and "-i br0".
                    let inline = letters
                        .get(offset.saturating_add(letter.len_utf8())..)
                        .unwrap_or_default();
                    let value = if inline.is_empty() {
                        match arguments.get(index) {
                            Some(value) => {
                                index = index.saturating_add(1);
                                value.clone()
                            }
                            None => {
                                return Outcome::Reject(format!(
                                    "Option -{letter} requires an argument."
                                ))
                            }
                        }
                    } else {
                        inline.to_owned()
                    };
                    if value.len() > MAX_OPTION_VALUE {
                        return Outcome::Reject(format!("Option -{letter} argument is too long"));
                    }
                    if let Some(reject) = apply_value(&mut options, letter, &value) {
                        return Outcome::Reject(reject);
                    }
                    // The value consumed the rest of this cluster.
                    break;
                }
                _ => {
                    return Outcome::Reject(format!(
                        "Bad option '{}'",
                        sanitise(&letter.to_string())
                    ))
                }
            }
        }
    }

    if !families.v4 && !families.v6 {
        families = Families { v4: true, v6: true };
    }
    if !transports.udp && !transports.tcp {
        transports = Transports {
            udp: true,
            tcp: true,
        };
    }
    if !protocols.llmnr && !protocols.wsd {
        protocols = Protocols {
            llmnr: true,
            wsd: true,
        };
    }
    options.families = families;
    options.transports = transports;
    options.protocols = protocols;
    Outcome::Run(Box::new(options))
}

fn apply_value(options: &mut Options, letter: char, value: &str) -> Option<String> {
    match letter {
        'i' => {
            // `wsdd2.c:800`: an empty name or the literal "any" means every
            // interface.  A name that is not a legal interface name is a
            // startup failure, exactly as `if_nametoindex` failing was.
            if value.is_empty() || value == "any" {
                options.interface = None;
            } else if !interface_name_is_legal(value) {
                return Some(format!("Bad interface '{}'", sanitise(value)));
            } else {
                options.interface = Some(value.to_owned());
            }
        }
        'H' => options.hostname = non_empty(value, options.hostname.take()),
        'N' => options.netbios_name = non_empty(value, options.netbios_name.take()),
        'G' => options.workgroup = non_empty(value, options.workgroup.take()),
        'b' => {
            if let Err(bad) = apply_boot_info(&mut options.boot, value) {
                return Some(format!("Bad key:val '{}'", sanitise(&bad)));
            }
        }
        _ => {}
    }
    None
}

fn non_empty(value: &str, previous: Option<String>) -> Option<String> {
    // `wsdd2.c:806`: an empty argument leaves the previous value in place.
    if value.is_empty() {
        previous
    } else {
        Some(value.to_owned())
    }
}

/// A legal Linux interface name: 1..=15 bytes, no NUL, no slash, no space.
#[must_use]
pub fn interface_name_is_legal(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 16
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'/' && byte != b':')
}

/// Longest accepted `-b` value, per key.
pub const MAX_BOOT_VALUE: usize = 64;

/// Merges a `-b "key1:val1,key2:val2"` string over the defaults.
///
/// `wsd.c:195-259` walked the same grammar but stored the value with
/// `strndup(val, vallen + 1)`, one byte past the end of the value.
///
/// # Errors
/// Returns the offending fragment.
pub fn apply_boot_info(boot: &mut BootInfo, argument: &str) -> Result<(), String> {
    for pair in argument.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let Some((key, value)) = pair.split_once(':') else {
            return Err(pair.to_owned());
        };
        let key = key.trim();
        let value = value.trim();
        if value.is_empty() || value.len() > MAX_BOOT_VALUE {
            return Err(pair.to_owned());
        }
        // The value is published inside XML; keep it to bytes that carry no
        // markup meaning even though the encoder escapes it anyway.
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        {
            return Err(pair.to_owned());
        }
        let slot = match key {
            "vendor" => &mut boot.vendor,
            "model" => &mut boot.model,
            "serial" => &mut boot.serial,
            "sku" => &mut boot.sku,
            "vendorurl" => &mut boot.vendor_url,
            "modelurl" => &mut boot.model_url,
            "presentationurl" => &mut boot.presentation_url,
            _ => return Err(pair.to_owned()),
        };
        *slot = value.to_owned();
    }
    Ok(())
}

/// Replaces every byte that is not printable ASCII, so a hostile argument
/// cannot forge a log line or a terminal escape.
#[must_use]
pub fn sanitise(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_graphic() || character == ' ' {
                character
            } else {
                '?'
            }
        })
        .take(MAX_OPTION_VALUE)
        .collect()
}

/// The usage text, matching `wsdd2.c:709-729`.
#[must_use]
pub fn usage(program: &str) -> String {
    let mut text = String::from("WSDD and LLMNR daemon\nUsage: ");
    text.push_str(&sanitise(program));
    text.push_str(
        " [options]\n\
         \x20      -h this message\n\
         \x20      -d become daemon\n\
         \x20      -4 IPv4 only\n\
         \x20      -6 IPv6 only\n\
         \x20      -u UDP only\n\
         \x20      -t TCP only\n\
         \x20      -l LLMNR only\n\
         \x20      -w WSDD only\n\
         \x20      -L increment LLMNR debug level\n\
         \x20      -W increment WSDD debug level\n\
         \x20      -i <interface> reply only on this interface\n\
         \x20      -H <name> set host name\n\
         \x20      -N <name> set netbios name\n\
         \x20      -G <name> set workgroup\n\
         \x20      -b \"key1:val1,key2:val2,...\" boot parameters:\n\
         \x20          vendor: model: serial: sku: vendorurl: modelurl: presentationurl:\n\
         \x20      --self-test run the offline protocol self-test and exit\n",
    );
    text
}
