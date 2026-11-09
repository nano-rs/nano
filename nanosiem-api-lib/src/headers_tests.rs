// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5015: the shared client-IP extractor believes forwarded headers only
//! from a trusted proxy, and only the headers an operator opted in to.

use std::net::SocketAddr;

use axum::http::HeaderMap;

use super::{extract_client_ip_with, parse_trusted_client_ip_headers, ClientIp, ClientIpHeader};

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.insert(
            axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            v.parse().unwrap(),
        );
    }
    h
}

fn peer(ip: &str) -> SocketAddr {
    format!("{ip}:44321").parse().unwrap()
}

fn spoof() -> HeaderMap {
    headers(&[
        ("CF-Connecting-IP", "127.0.0.1"),
        ("True-Client-IP", "127.0.0.1"),
        ("X-Real-IP", "127.0.0.1"),
        ("X-Forwarded-For", "127.0.0.1, 203.0.113.9"),
    ])
}

#[test]
fn an_untrusted_peer_is_never_believed() {
    let default = parse_trusted_client_ip_headers(None);
    let got = extract_client_ip_with(&spoof(), Some(&peer("198.51.100.7")), &default, false);
    assert_eq!(
        got,
        Some(ClientIp { ip: "198.51.100.7".into(), from_socket: true }),
        "a direct caller's forwarded headers must be ignored"
    );
}

#[test]
fn a_trusted_proxy_is_believed_only_for_x_forwarded_for_by_default() {
    let default = parse_trusted_client_ip_headers(None);
    assert_eq!(default, vec![ClientIpHeader::XForwardedFor]);
    let got = extract_client_ip_with(&spoof(), Some(&peer("172.18.0.5")), &default, true);
    // Rightmost XFF entry (the one the proxy appended), NOT the CF / True-Client
    // loopback claim, and flagged as header-derived.
    assert_eq!(got, Some(ClientIp { ip: "203.0.113.9".into(), from_socket: false }));
}

#[test]
fn cdn_headers_are_honoured_only_after_opt_in() {
    let opted = parse_trusted_client_ip_headers(Some("cf-connecting-ip, X-Forwarded-For"));
    assert_eq!(opted, vec![ClientIpHeader::CfConnectingIp, ClientIpHeader::XForwardedFor]);
    let h = headers(&[("CF-Connecting-IP", "192.0.2.44"), ("X-Forwarded-For", "203.0.113.9")]);
    let got = extract_client_ip_with(&h, Some(&peer("10.0.0.2")), &opted, true);
    assert_eq!(got, Some(ClientIp { ip: "192.0.2.44".into(), from_socket: false }));
    // Still never from an untrusted peer.
    let got = extract_client_ip_with(&h, Some(&peer("198.51.100.7")), &opted, false);
    assert_eq!(got.unwrap().ip, "198.51.100.7");
}

#[test]
fn a_trusted_proxy_without_forwarded_headers_falls_back_to_the_socket() {
    let default = parse_trusted_client_ip_headers(None);
    let got = extract_client_ip_with(&HeaderMap::new(), Some(&peer("127.0.0.1")), &default, true);
    assert_eq!(got, Some(ClientIp { ip: "127.0.0.1".into(), from_socket: true }));
    assert_eq!(extract_client_ip_with(&HeaderMap::new(), None, &default, true), None);
}

#[test]
fn unknown_or_empty_header_lists_fall_back_to_the_default() {
    assert_eq!(
        parse_trusted_client_ip_headers(Some("x-evil, ")),
        vec![ClientIpHeader::XForwardedFor]
    );
    assert_eq!(parse_trusted_client_ip_headers(Some("")), vec![ClientIpHeader::XForwardedFor]);
}
