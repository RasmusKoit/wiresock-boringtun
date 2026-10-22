// Copyright (c) 2024-2026 WireSock. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! AmneziaWG 1.5/2.0 signature packets I1..I5 through `Tunn`: their place in
//! the pre-handshake burst (ahead of the Jc junk, which is ahead of the
//! initiation, as amneziawg-go's `SendHandshakeInitiation` sends them), their
//! regeneration for every burst, a responder's indifference to them, and a
//! handshake between a client that sends them and a server that does not.
//! The tag language itself is tested in `signature`.

use super::amnezia::{AmneziaConfig, PendingBurstChange};
use super::*;
use rand_core::{OsRng, RngCore};

fn pair(client: AmneziaConfig, server: AmneziaConfig) -> (Tunn, Tunn) {
    let c_sk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let c_pk = x25519_dalek::PublicKey::from(&c_sk);
    let s_sk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let s_pk = x25519_dalek::PublicKey::from(&s_sk);
    let mk = |sk, pk, cfg| {
        Tunn::new_with_amnezia(
            sk,
            pk,
            None,
            None,
            OsRng.next_u32() >> 8,
            None,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            cfg,
        )
        .unwrap()
    };
    (mk(c_sk, s_pk, client), mk(s_sk, c_pk, server))
}

fn plain() -> AmneziaConfig {
    AmneziaConfig::new(0, 0, 0, 0)
}

fn ipv4(seq: u8) -> Vec<u8> {
    let header = etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 3], 64)
        .udp(4000 + seq as u16, 53);
    let payload = [seq; 40];
    let mut p = Vec::new();
    header.write(&mut p, &payload).unwrap();
    p
}

fn net(r: TunnResult<'_>) -> Vec<u8> {
    match r {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => panic!("expected a datagram for the network, got {:?}", other),
    }
}

fn delivered(r: TunnResult<'_>) -> Vec<u8> {
    match r {
        TunnResult::WriteToTunnelV4(p, _) => p.to_vec(),
        other => panic!("expected a delivered packet, got {:?}", other),
    }
}

/// `datagram` is a handshake initiation under `tunn`'s framing.
fn is_initiation(tunn: &Tunn, datagram: &[u8]) -> bool {
    matches!(
        Tunn::parse_incoming_packet(tunn.handshake.obf, datagram),
        Ok(Packet::HandshakeInit(_))
    )
}

fn unix_now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

fn specs<'a>(i1: &'a str, i2: &'a str) -> [Option<&'a str>; 5] {
    [Some(i1), Some(i2), None, None, None]
}

/// With I1 and I2 set and Jc = 2, a drain yields the two signature datagrams,
/// then two junk datagrams, then the initiation, in that order.
#[test]
fn signature_packets_lead_the_burst_ahead_of_the_jc_junk_and_the_initiation() {
    let client = plain()
        .with_pre_handshake_junk(2, 100, 100, 0)
        .with_signature_packets(specs("<b 0xdeadbeef><rc 4>", "<rd 3><b 0x0102>"))
        .unwrap();
    assert_eq!(client.validate(), Ok(()));
    let (mut c, mut s) = pair(client, plain());
    let mut buf = [0u8; 2048];

    // The first write opens the burst and queues the packet; every later
    // datagram is drained with an empty decapsulate.
    let i1 = net(c.encapsulate(&ipv4(1), &mut buf));
    assert_eq!(i1.len(), 8, "I1 is <b 0xdeadbeef> plus four letters");
    assert_eq!(&i1[..4], &[0xde, 0xad, 0xbe, 0xef]);
    assert!(i1[4..].iter().all(u8::is_ascii_alphabetic), "{:?}", i1);

    let i2 = net(c.decapsulate(None, &[], &mut buf));
    assert_eq!(i2.len(), 5, "I2 is three digits plus <b 0x0102>");
    assert!(i2[..3].iter().all(u8::is_ascii_digit), "{:?}", i2);
    assert_eq!(&i2[3..], &[0x01, 0x02]);

    let j1 = net(c.decapsulate(None, &[], &mut buf));
    let j2 = net(c.decapsulate(None, &[], &mut buf));
    assert_eq!((j1.len(), j2.len()), (100, 100), "two Jc junk datagrams");

    let init = net(c.decapsulate(None, &[], &mut buf));
    assert_eq!(init.len(), HANDSHAKE_INIT_SZ);
    assert!(is_initiation(&c, &init));
    assert!(c.pending_amnezia_junk.is_none(), "the burst is spent");

    // The server never asked for any of it: each datagram ahead of the
    // initiation is refused, and the handshake then completes on the
    // initiation alone.
    for junk in [&i1, &i2, &j1, &j2] {
        assert!(
            matches!(s.decapsulate(None, junk, &mut buf), TunnResult::Err(_)),
            "a server refuses a datagram it cannot read"
        );
    }
    let response = net(s.decapsulate(None, &init, &mut buf));
    let keepalive = net(c.decapsulate(None, &response, &mut buf));
    assert!(matches!(
        s.decapsulate(None, &keepalive, &mut buf),
        TunnResult::Done
    ));
    // The write that opened the burst is still owed, and now goes out.
    let data = net(c.decapsulate(None, &[], &mut buf));
    assert_eq!(delivered(s.decapsulate(None, &data, &mut buf)), ipv4(1));
}

/// Every burst generates the signature datagrams anew: a retransmission
/// carries fresh random bytes and the time it was built, never the first
/// burst's bytes again.
#[test]
fn every_burst_regenerates_the_signature_packets() {
    let client = plain()
        .with_signature_packets([Some("<b 0x01><r 16><t>"), None, None, None, None])
        .unwrap();
    let (mut c, _s) = pair(client, plain());
    let mut buf = [0u8; 2048];

    let first = net(c.format_handshake_initiation(&mut buf, false));
    assert_eq!(first.len(), 1 + 16 + 4);
    let init = net(c.format_handshake_initiation(&mut buf, false));
    assert!(is_initiation(&c, &init));

    // A forced resend is what the handshake retransmission timer does.
    let before = unix_now();
    let second = net(c.format_handshake_initiation(&mut buf, true));
    assert_eq!(second.len(), 21);
    let init = net(c.format_handshake_initiation(&mut buf, true));
    assert!(is_initiation(&c, &init));

    assert_eq!((first[0], second[0]), (0x01, 0x01));
    assert_ne!(first[1..17], second[1..17], "fresh random bytes per burst");
    let stamp = u32::from_be_bytes([second[17], second[18], second[19], second[20]]);
    assert!(
        before <= stamp && stamp <= unix_now(),
        "the timestamp is the time of the burst"
    );
}

/// A responder drops the signature packets with the rest of the pre-handshake
/// burst: its first datagram is the initiation.
#[test]
fn a_responder_sends_the_initiation_first() {
    let client = plain()
        .with_pre_handshake_junk(2, 100, 100, 0)
        .with_signature_packets(specs("<b 0xdeadbeef>", "<rc 8>"))
        .unwrap();
    let server = client.clone().as_responder();
    assert!(
        server.signature_packets().iter().all(Option::is_none),
        "as_responder drops them"
    );
    assert_eq!(client.signature_packets().iter().flatten().count(), 2);

    let (mut s, _c) = pair(server, plain());
    let mut buf = [0u8; 2048];
    let first = net(s.format_handshake_initiation(&mut buf, false));
    assert_eq!(first.len(), HANDSHAKE_INIT_SZ);
    assert!(is_initiation(&s, &first));
}

/// A client sending signature packets and a server that knows nothing of them
/// handshake and exchange data both ways, under S1-S4 framing.
#[test]
fn a_client_with_signature_packets_talks_to_a_server_without() {
    let server = AmneziaConfig::new(10, 20, 30, 40);
    let client = server
        .clone()
        .with_pre_handshake_junk(1, 50, 60, 0)
        .with_signature_packets([
            Some("<b 0x16030100><r 32>"),
            None,
            Some("<rc 12>"),
            None,
            Some("<t><rd 6>"),
        ])
        .unwrap();
    let (mut c, mut s) = pair(client, server);
    let mut buf = [0u8; 2048];

    // I1, I3, I5, one junk datagram, then the S1-framed initiation.
    let mut burst = vec![net(c.format_handshake_initiation(&mut buf, false))];
    while c.pending_amnezia_junk.is_some() {
        burst.push(net(c.format_handshake_initiation(&mut buf, false)));
    }
    assert_eq!(burst.len(), 5);
    assert_eq!(burst[0].len(), 36);
    assert_eq!(&burst[0][..4], &[0x16, 0x03, 0x01, 0x00]);
    assert_eq!(burst[1].len(), 12);
    assert_eq!(burst[2].len(), 10);
    assert!((50..=60).contains(&burst[3].len()));
    assert_eq!(burst[4].len(), 10 + HANDSHAKE_INIT_SZ);

    let response = net(s.decapsulate(None, &burst[4], &mut buf));
    let keepalive = net(c.decapsulate(None, &response, &mut buf));
    assert!(matches!(
        s.decapsulate(None, &keepalive, &mut buf),
        TunnResult::Done
    ));

    let to_server = net(c.encapsulate(&ipv4(7), &mut buf));
    assert_eq!(
        delivered(s.decapsulate(None, &to_server, &mut buf)),
        ipv4(7)
    );
    let to_client = net(s.encapsulate(&ipv4(8), &mut buf));
    assert_eq!(
        delivered(c.decapsulate(None, &to_client, &mut buf)),
        ipv4(8)
    );
}

/// The builder names the slot an error came from, treats a tag-less spec as
/// unset, and the configuration accounts for the packets where it must.
#[test]
fn the_builder_and_the_configuration_account_for_the_packets() {
    let err = plain()
        .with_signature_packets([None, Some("<x 1>"), None, None, Some("<r 2")])
        .unwrap_err();
    assert_eq!(err, "I2: unknown tag <x>");

    let cfg = plain()
        .with_signature_packets([Some(""), Some("<r 300>"), None, Some("<t>"), None])
        .unwrap();
    assert!(
        cfg.signature_packets()[0].is_none(),
        "an empty value is unset"
    );
    assert_eq!(cfg.signature_packets()[1].as_ref().unwrap().max_len(), 300);
    assert_eq!(cfg.signature_packets()[3].as_ref().unwrap().spec(), "<t>");
    assert_eq!(cfg.validate(), Ok(()));
    assert!(cfg.emits_pre_handshake());
    assert!(!plain().emits_pre_handshake());

    // The largest datagram the burst's generated part can produce.
    assert_eq!(cfg.pre_handshake_junk_max_size(), 300);
    assert_eq!(
        cfg.clone()
            .with_pre_handshake_junk(2, 100, 100, 0)
            .pre_handshake_junk_max_size(),
        300
    );
    assert_eq!(
        cfg.clone()
            .with_pre_handshake_junk(2, 100, 900, 0)
            .pre_handshake_junk_max_size(),
        900
    );

    // A live change to them rebuilds a pending burst, which generated them.
    assert_eq!(
        cfg.pending_burst_change(&cfg.clone()),
        PendingBurstChange::Keep
    );
    let changed = cfg
        .clone()
        .with_signature_packets([None, Some("<r 300>"), None, Some("<t>"), None])
        .unwrap();
    assert_eq!(cfg.pending_burst_change(&changed), PendingBurstChange::Keep);
    let changed = cfg
        .clone()
        .with_signature_packets([None, Some("<r 301>"), None, Some("<t>"), None])
        .unwrap();
    assert_eq!(
        cfg.pending_burst_change(&changed),
        PendingBurstChange::Restart
    );
}
