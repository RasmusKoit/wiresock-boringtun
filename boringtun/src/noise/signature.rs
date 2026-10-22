// Copyright (c) 2024-2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! AmneziaWG 1.5/2.0 custom signature packets, `I1`..`I5`.
//!
//! Each is a standalone datagram a client sends ahead of every handshake
//! initiation, before the Jc junk: a sequence of tags that is generated afresh
//! for each burst (new random bytes, the current time). The server never
//! checks for them -- they shape what an observer sees, nothing else -- so a
//! responder has no use for them and [`crate::noise::amnezia::AmneziaConfig::as_responder`]
//! drops them.
//!
//! The grammar is amneziawg-go's `device/obf.go` and the `obf_*.go` builders
//! (see its README, "Custom signature packets"), mirrored tag for tag:
//!
//! * `<b 0xHEX>` -- the bytes `HEX` encodes, two hex digits per byte, upper or
//!   lower case. The `0x` prefix is optional. An odd number of digits, no
//!   digits at all, or a non-hex character is an error.
//! * `<r N>` -- `N` random bytes.
//! * `<rd N>` -- `N` random ASCII digits, `0`..`9`.
//! * `<rc N>` -- `N` random ASCII letters, `a`..`z` and `A`..`Z`.
//! * `<t>` -- the current unix time as a 4-byte **big-endian** unsigned
//!   integer (`binary.BigEndian.PutUint32(dst, uint32(time.Now().Unix()))`).
//!
//! Tags are found by scanning for `<`; anything outside a tag is skipped, as
//! amneziawg-go skips it, and a `<` with no `>` after it fails the whole spec.
//! Inside a tag the fields are split on whitespace: the first is the tag
//! name, the second its argument, and any further fields are ignored, so
//! `< b   0x01 extra >` is `<b 0x01>`. A size is a non-negative decimal
//! integer (amneziawg-go's `strconv.Atoi`; a negative size, which it would
//! only reject at send time, is refused here). A spec with no tags at all,
//! an empty string included, is "unset": amneziawg-go builds no packet from
//! it, and neither does [`SignaturePacket::parse`], which returns `Ok(None)`.
//!
//! Two bounds amneziawg-go does not apply: a packet is refused if it would be
//! empty (an empty datagram is this crate's "drain" request, never something
//! to send), or if it would exceed the largest datagram a UDP socket can
//! carry (`MAX_SENDABLE_DATAGRAM`, 65507 bytes), where it could never be sent.
//! Its data tags (`<d>`, `<ds>`, `<dz N>`) are not accepted: they describe an
//! enclosed payload, and a signature packet carries none.

use super::amnezia::MAX_SENDABLE_DATAGRAM;
use rand_core::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};

/// The number of signature packet slots, `I1`..`I5`.
pub const SIGNATURE_PACKET_SLOTS: usize = 5;

/// amneziawg-go's `chars52`: the `<rc>` alphabet, in its order, so a byte
/// drawn as `b % 52` lands on the same letter.
const CHARS52: &[u8; 52] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// amneziawg-go's `digits10`: the `<rd>` alphabet.
const DIGITS10: &[u8; 10] = b"0123456789";
/// The bytes `<t>` writes.
const TIMESTAMP_LEN: usize = 4;

/// One tag of a signature packet, already parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tag {
    /// `<b 0x..>`: these bytes, as they are.
    Bytes(Vec<u8>),
    /// `<r N>`: `N` random bytes.
    Random(usize),
    /// `<rd N>`: `N` random ASCII digits.
    RandomDigits(usize),
    /// `<rc N>`: `N` random ASCII letters.
    RandomChars(usize),
    /// `<t>`: the current unix time, 4 bytes big-endian.
    Timestamp,
}

impl Tag {
    /// How many bytes this tag writes. Every tag has a fixed length.
    fn len(&self) -> usize {
        match self {
            Tag::Bytes(bytes) => bytes.len(),
            Tag::Random(n) | Tag::RandomDigits(n) | Tag::RandomChars(n) => *n,
            Tag::Timestamp => TIMESTAMP_LEN,
        }
    }

    /// Append this tag's bytes to `out`, drawing from `rng` where the tag is
    /// random. amneziawg-go draws a random byte per character and reduces it
    /// modulo the alphabet (`chars52[dst[i]%52]`), and so does this -- the
    /// slight bias toward the alphabet's first entries is part of the
    /// imitated shape.
    fn write(&self, out: &mut Vec<u8>, rng: &mut impl RngCore) {
        match self {
            Tag::Bytes(bytes) => out.extend_from_slice(bytes),
            Tag::Random(n) => {
                let start = out.len();
                out.resize(start + n, 0);
                rng.fill_bytes(&mut out[start..]);
            }
            Tag::RandomDigits(n) => Self::write_from_alphabet(out, *n, DIGITS10, rng),
            Tag::RandomChars(n) => Self::write_from_alphabet(out, *n, CHARS52, rng),
            Tag::Timestamp => out.extend_from_slice(&unix_time_now().to_be_bytes()),
        }
    }

    fn write_from_alphabet(out: &mut Vec<u8>, n: usize, alphabet: &[u8], rng: &mut impl RngCore) {
        let start = out.len();
        out.resize(start + n, 0);
        rng.fill_bytes(&mut out[start..]);
        for b in &mut out[start..] {
            *b = alphabet[*b as usize % alphabet.len()];
        }
    }
}

/// The current unix time, truncated to 32 bits as `uint32(time.Now().Unix())`
/// truncates it. A clock before 1970 reads as 0.
fn unix_time_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs() as u32)
        .unwrap_or(0)
}

/// A parsed `I1`..`I5` value: the tags, in order, and the spec they came
/// from, which is what `awg showconf` prints back.
///
/// Build one with [`SignaturePacket::parse`]; generate a datagram from it with
/// [`SignaturePacket::generate`], once per burst.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignaturePacket {
    spec: String,
    tags: Vec<Tag>,
    len: usize,
}

impl SignaturePacket {
    /// Parse a spec in the tag language of the module documentation.
    ///
    /// `Ok(None)` is a spec with no tags in it, which amneziawg-go treats as
    /// the packet being unset. `Err` names every offending tag, as
    /// amneziawg-go's `errors.Join` does, one per `; `.
    pub fn parse(spec: &str) -> Result<Option<Self>, String> {
        let mut tags = Vec::new();
        let mut errors = Vec::new();

        let mut remaining = spec;
        while let Some(start) = remaining.find('<') {
            let end = match remaining[start..].find('>') {
                Some(end) => start + end,
                None => return Err("missing enclosing >".to_owned()),
            };
            let tag = &remaining[start + 1..end];
            remaining = &remaining[end + 1..];

            let mut fields = tag.split_whitespace();
            let key = match fields.next() {
                Some(key) => key,
                None => {
                    errors.push("empty tag".to_owned());
                    continue;
                }
            };
            let val = fields.next().unwrap_or("");

            let built = match key {
                "b" => parse_bytes(val).map(Tag::Bytes),
                "t" => Ok(Tag::Timestamp),
                "r" => parse_size(val).map(Tag::Random),
                "rc" => parse_size(val).map(Tag::RandomChars),
                "rd" => parse_size(val).map(Tag::RandomDigits),
                _ => {
                    errors.push(format!("unknown tag <{}>", key));
                    continue;
                }
            };
            match built {
                Ok(tag) => tags.push(tag),
                Err(e) => errors.push(format!("failed to build <{}>: {}", key, e)),
            }
        }

        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        if tags.is_empty() {
            return Ok(None);
        }

        let len = tags.iter().map(Tag::len).sum::<usize>();
        if len == 0 {
            return Err("the packet would be empty".to_owned());
        }
        if len > MAX_SENDABLE_DATAGRAM {
            return Err(format!(
                "the packet would be {} bytes, more than the {} a UDP datagram can carry",
                len, MAX_SENDABLE_DATAGRAM
            ));
        }

        Ok(Some(Self {
            spec: spec.to_owned(),
            tags,
            len,
        }))
    }

    /// The spec this was parsed from, verbatim.
    pub fn spec(&self) -> &str {
        &self.spec
    }

    /// The size of the datagram [`Self::generate`] produces. Every tag has a
    /// fixed length, so this is exact, and never 0 or above
    /// `MAX_SENDABLE_DATAGRAM`.
    pub fn max_len(&self) -> usize {
        self.len
    }

    /// A fresh datagram: new random bytes, the time of the call. Called once
    /// for each burst the packet goes out in, never cached across bursts.
    pub fn generate(&self, rng: &mut impl RngCore) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.len);
        for tag in &self.tags {
            tag.write(&mut out, rng);
        }
        debug_assert_eq!(out.len(), self.len);
        out
    }
}

/// `<b>`'s argument: `obf_bytes.go`'s `newBytesObf`.
fn parse_bytes(val: &str) -> Result<Vec<u8>, String> {
    let val = val.strip_prefix("0x").unwrap_or(val);
    if val.is_empty() {
        return Err("empty argument".to_owned());
    }
    if val.len() % 2 != 0 {
        return Err("odd amount of symbols".to_owned());
    }
    hex::decode(val).map_err(|e| e.to_string())
}

/// A size argument: `strconv.Atoi`, less the negative numbers.
fn parse_size(val: &str) -> Result<usize, String> {
    if val.is_empty() {
        return Err("missing size".to_owned());
    }
    val.parse::<usize>()
        .map_err(|_| format!("invalid size \"{}\"", val))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    fn rng() -> ChaCha8Rng {
        ChaCha8Rng::seed_from_u64(0x5151)
    }

    fn packet(spec: &str) -> SignaturePacket {
        SignaturePacket::parse(spec)
            .unwrap_or_else(|e| panic!("{:?} should parse: {}", spec, e))
            .unwrap_or_else(|| panic!("{:?} should set a packet", spec))
    }

    fn rejected(spec: &str) -> String {
        match SignaturePacket::parse(spec) {
            Err(e) => e,
            Ok(p) => panic!("{:?} should be refused, parsed as {:?}", spec, p),
        }
    }

    fn now() -> u32 {
        unix_time_now()
    }

    #[test]
    fn static_bytes_are_dumped_as_they_are() {
        assert_eq!(packet("<b 0x0102>").generate(&mut rng()), [0x01, 0x02]);
        // The 0x prefix is optional and hex digits may be upper case.
        assert_eq!(packet("<b 0102>").generate(&mut rng()), [0x01, 0x02]);
        assert_eq!(
            packet("<b 0xDEADbeef>").generate(&mut rng()),
            [0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(packet("<b 0x0102>").max_len(), 2);
        assert_eq!(packet("<b 0x0102>").spec(), "<b 0x0102>");
    }

    #[test]
    fn random_bytes_come_from_the_rng() {
        let p = packet("<r 5>");
        assert_eq!(p.max_len(), 5);
        let got = p.generate(&mut rng());
        let mut expected = [0u8; 5];
        rng().fill_bytes(&mut expected);
        assert_eq!(got, expected);
    }

    #[test]
    fn random_digits_are_ascii_digits() {
        let p = packet("<rd 4>");
        assert_eq!(p.max_len(), 4);
        let mut r = rng();
        for _ in 0..100 {
            let got = p.generate(&mut r);
            assert_eq!(got.len(), 4);
            assert!(got.iter().all(u8::is_ascii_digit), "{:?}", got);
        }
        // The same draw as amneziawg-go: a byte per digit, reduced modulo 10.
        let mut raw = [0u8; 4];
        rng().fill_bytes(&mut raw);
        let expected: Vec<u8> = raw.iter().map(|b| b'0' + b % 10).collect();
        assert_eq!(p.generate(&mut rng()), expected);
    }

    #[test]
    fn random_chars_are_ascii_letters() {
        let p = packet("<rc 6>");
        assert_eq!(p.max_len(), 6);
        let mut r = rng();
        for _ in 0..100 {
            let got = p.generate(&mut r);
            assert_eq!(got.len(), 6);
            assert!(got.iter().all(u8::is_ascii_alphabetic), "{:?}", got);
        }
        let mut raw = [0u8; 6];
        rng().fill_bytes(&mut raw);
        let expected: Vec<u8> = raw.iter().map(|b| CHARS52[*b as usize % 52]).collect();
        assert_eq!(p.generate(&mut rng()), expected);
    }

    #[test]
    fn the_timestamp_is_the_unix_time_big_endian() {
        let p = packet("<t>");
        assert_eq!(p.max_len(), 4);
        let before = now();
        let got = p.generate(&mut rng());
        let after = now();
        assert_eq!(got.len(), 4);
        let stamp = u32::from_be_bytes([got[0], got[1], got[2], got[3]]);
        assert!(
            before <= stamp && stamp <= after,
            "{} not within {}..={}",
            stamp,
            before,
            after
        );
        // Big-endian: the most significant byte first, as `binary.BigEndian`
        // writes it, so the current time starts with the high byte.
        assert_eq!(got[0], (stamp >> 24) as u8);
        assert_eq!(got[3], stamp as u8);
    }

    #[test]
    fn a_mixed_spec_lays_its_tags_out_in_order() {
        let p = packet("<b 0xaa><rd 2><t><r 3><rc 1>");
        assert_eq!(p.max_len(), 1 + 2 + 4 + 3 + 1);
        let before = now();
        let got = p.generate(&mut rng());
        assert_eq!(got.len(), 11);
        assert_eq!(got[0], 0xaa);
        assert!(got[1..3].iter().all(u8::is_ascii_digit));
        let stamp = u32::from_be_bytes([got[3], got[4], got[5], got[6]]);
        assert!(stamp >= before && stamp <= now());
        assert!(got[10].is_ascii_alphabetic());
        // Two generations differ in their random parts and nothing else.
        let again = p.generate(&mut rng());
        assert_eq!(again.len(), 11);
        assert_eq!(again[0], 0xaa);
    }

    #[test]
    fn whitespace_and_text_outside_tags_follow_amneziawg_go() {
        // Fields are split on any whitespace; a third field is ignored.
        assert_eq!(packet("< b \t 0x01   extra >").generate(&mut rng()), [1]);
        // Text outside the tags is skipped, not an error.
        assert_eq!(
            packet("junk <b 0x01> more <b 0x02>").generate(&mut rng()),
            [1, 2]
        );
        assert_eq!(packet("<b 0x01>\n<b 0x02>").generate(&mut rng()), [1, 2]);
        // The spec is kept verbatim for `awg showconf`.
        assert_eq!(packet(" <b 0x01> ").spec(), " <b 0x01> ");
        // A leading `+` is a sign `strconv.Atoi` accepts.
        assert_eq!(packet("<r +2>").max_len(), 2);
        // A zero-length tag beside others is fine; the packet is not empty.
        assert_eq!(packet("<r 0><b 0x01>").generate(&mut rng()), [1]);
    }

    #[test]
    fn a_spec_without_tags_is_unset() {
        assert_eq!(SignaturePacket::parse(""), Ok(None));
        assert_eq!(SignaturePacket::parse("   "), Ok(None));
        assert_eq!(SignaturePacket::parse("no tags here"), Ok(None));
    }

    #[test]
    fn rejected_specs_name_the_offending_tag() {
        assert_eq!(
            rejected("<b 0x012>"),
            "failed to build <b>: odd amount of symbols"
        );
        assert_eq!(rejected("<b 0x>"), "failed to build <b>: empty argument");
        assert_eq!(rejected("<b>"), "failed to build <b>: empty argument");
        assert!(
            rejected("<b 0xzz>").starts_with("failed to build <b>: "),
            "{}",
            rejected("<b 0xzz>")
        );
        assert_eq!(rejected("<x 1>"), "unknown tag <x>");
        // The data tags are amneziawg-go's, but not for a signature packet.
        assert_eq!(rejected("<d>"), "unknown tag <d>");
        assert_eq!(rejected("<r>"), "failed to build <r>: missing size");
        assert_eq!(rejected("<rc>"), "failed to build <rc>: missing size");
        assert_eq!(
            rejected("<rd -1>"),
            "failed to build <rd>: invalid size \"-1\""
        );
        assert_eq!(
            rejected("<r 1.5>"),
            "failed to build <r>: invalid size \"1.5\""
        );
        assert_eq!(rejected("<b 0x01"), "missing enclosing >");
        assert_eq!(rejected("<b 0x01><r 2"), "missing enclosing >");
        assert_eq!(rejected("<>"), "empty tag");
        assert_eq!(rejected("<  >"), "empty tag");
        // Every bad tag is reported, as `errors.Join` reports them.
        assert_eq!(
            rejected("<x 1><b 0x1>"),
            "unknown tag <x>; failed to build <b>: odd amount of symbols"
        );
    }

    #[test]
    fn the_packet_is_bounded_by_what_a_datagram_can_carry() {
        assert_eq!(rejected("<r 0>"), "the packet would be empty");
        assert_eq!(rejected("<rd 0><rc 0>"), "the packet would be empty");
        assert_eq!(packet("<r 65507>").max_len(), MAX_SENDABLE_DATAGRAM);
        assert_eq!(
            rejected("<r 65508>"),
            "the packet would be 65508 bytes, more than the 65507 a UDP datagram can carry"
        );
        assert!(rejected("<r 65500><t><rd 4>").starts_with("the packet would be 65508 bytes"));
    }
}
