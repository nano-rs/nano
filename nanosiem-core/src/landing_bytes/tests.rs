// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use sha2_10::{Digest, Sha256};
use std::{
    io::ErrorKind,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;

const BODY: &[u8] = b"owned-synthetic-landing";
fn header() -> RequestHeader {
    RequestHeader {
        schema_version: 1,
        request_id: 27,
        tenant_id: Uuid::parse_str("01234567-89ab-4cde-8fab-0123456789ab").unwrap(),
        source_id: Uuid::from_u128(28),
        source_revision: 3,
        credential_id: Uuid::from_u128(29),
        credential_revision: 4,
        route_key: "TENZIR.Source-_9".into(),
        format: Format::Parquet,
        partition_class: None,
        file_sha256: Sha256::digest(BODY).into(),
        conversion_id: Uuid::from_u128(30),
        received_unix_millis: 1_792_843_200_123,
    }
}
fn binding() -> RequestBinding {
    RequestBinding {
        request_id: 27,
        frame_sha256: [3; 32],
    }
}
fn summary(binding: RequestBinding) -> ResponseSummary {
    ResponseSummary {
        schema_version: 1,
        request_id: binding.request_id,
        request_frame_sha256: binding.frame_sha256,
        outcome: Outcome::Converted,
        refusal_reason: None,
        chunk_count: 2,
        rows_seen: 4,
        rows_accepted: 3,
        rows_refused: 1,
        rows_time_clamped: 1,
        rows_class_from_path: 3,
    }
}
fn request(json: &[u8], length: u64, body: &[u8]) -> Vec<u8> {
    let mut out = b"NLB1".to_vec();
    out.extend_from_slice(&(json.len() as u32).to_be_bytes());
    out.extend_from_slice(json);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(body);
    out
}
fn response(value: &ResponseSummary, parts: &[(u32, u32, u64, &[u8])]) -> Vec<u8> {
    let json = serde_json::to_vec(value).unwrap();
    let mut out = b"NLR1".to_vec();
    out.extend_from_slice(&(json.len() as u32).to_be_bytes());
    out.extend_from_slice(&json);
    for (ordinal, length, events, bytes) in parts {
        out.extend_from_slice(&ordinal.to_be_bytes());
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&events.to_be_bytes());
        out.extend_from_slice(bytes);
    }
    out
}
async fn receive(bytes: &[u8]) -> Result<ReceivedRequest, Error> {
    read_request(
        &mut &bytes[..],
        header().tenant_id,
        &ExchangeDeadline::new(),
    )
    .await
}

#[tokio::test]
async fn actual_unix_stream_request_response_half_closes_and_hashes_exact_frames() {
    let (mut root, mut leaf) = UnixStream::pair().unwrap();
    let deadline = ExchangeDeadline::new();
    let header = header();
    let tenant = header.tenant_id;
    let root_work = async {
        let sent = write_request(&mut root, &header, BODY, &deadline).await?;
        let received = read_response(&mut root, &sent, &deadline).await?;
        Ok::<_, Error>((sent, received))
    };
    let leaf_work = async {
        let input = read_request(&mut leaf, tenant, &deadline).await?;
        assert_eq!(input.header, header);
        assert_eq!(input.bytes, BODY);
        let parts = [
            ChunkRef {
                ordinal: 0,
                events: 1,
                bytes: b"opaque-a",
            },
            ChunkRef {
                ordinal: 1,
                events: 2,
                bytes: b"opaque-b",
            },
        ];
        let hash = write_response(&mut leaf, &summary(input.binding), &parts, &deadline).await?;
        Ok::<_, Error>((input.binding, hash))
    };
    let (root, leaf) = tokio::join!(root_work, leaf_work);
    let (sent, output) = root.unwrap();
    let (observed, hash) = leaf.unwrap();
    assert_eq!(sent, observed);
    assert_eq!(output.frame_sha256, hash);
    assert_eq!(output.chunks.len(), 2);
    assert_eq!(output.chunks[0].bytes, b"opaque-a");
    assert_eq!(output.chunks[1].events, 2);
    let wire = request(
        &serde_json::to_vec(&header).unwrap(),
        BODY.len() as u64,
        BODY,
    );
    let mut expected = Sha256::new();
    expected.update(b"nano-landing-request-v1\0");
    expected.update(wire);
    assert_eq!(sent.frame_sha256, <[u8; 32]>::from(expected.finalize()));
    let wire = response(
        &summary(sent),
        &[(0, 8, 1, b"opaque-a"), (1, 8, 2, b"opaque-b")],
    );
    let mut expected = Sha256::new();
    expected.update(b"nano-landing-response-v1\0");
    expected.update(wire);
    assert_eq!(output.frame_sha256, <[u8; 32]>::from(expected.finalize()));
}

#[tokio::test]
async fn refused_response_has_no_chunks_and_is_only_untrusted_data() {
    let mut value = summary(binding());
    value.outcome = Outcome::Refused;
    value.refusal_reason = Some(RefusalReason::OutputLimit);
    value.chunk_count = 0;
    value.rows_accepted = 0;
    value.rows_refused = 4;
    value.rows_time_clamped = 0;
    let (mut writer, mut reader) = UnixStream::pair().unwrap();
    let deadline = ExchangeDeadline::new();
    let expected = binding();
    let (written, read) = tokio::join!(
        write_response(&mut writer, &value, &[], &deadline),
        read_response(&mut reader, &expected, &deadline)
    );
    let output = read.unwrap();
    assert_eq!(written.unwrap(), output.frame_sha256);
    assert!(output.chunks.is_empty());
    assert_eq!(output.summary, value);
}

#[tokio::test]
async fn request_rejects_magic_truncation_and_unbounded_lengths_before_body_reads() {
    let mut metadata_large = b"NLB1".to_vec();
    metadata_large.extend_from_slice(&(MAX_METADATA_BYTES as u32 + 1).to_be_bytes());
    assert_eq!(receive(&metadata_large).await.unwrap_err(), Error::Limit);
    assert_eq!(receive(b"NLB").await.unwrap_err(), Error::Truncated);
    assert_eq!(receive(b"HTTP").await.unwrap_err(), Error::Invalid);
    let json = serde_json::to_vec(&header()).unwrap();
    for length in [0, MAX_INPUT_BYTES as u64 + 1, u64::MAX] {
        assert_eq!(
            receive(&request(&json, length, b"")).await.unwrap_err(),
            Error::Limit
        );
    }
    assert_eq!(
        receive(&request(&json, 5, b"a")).await.unwrap_err(),
        Error::Truncated
    );
}

#[tokio::test]
async fn unknown_duplicate_and_missing_nullable_fields_are_not_silently_normalized() {
    let json = serde_json::to_string(&header()).unwrap();
    for prefix in [
        r#""native_key":"UNTRUSTED_SENTINEL","#,
        r#""request_id":27,"#,
        r#""partition_class":null,"#,
    ] {
        let bad = format!("{{{prefix}{}", &json[1..]);
        assert_eq!(
            receive(&request(bad.as_bytes(), 0, b"")).await.unwrap_err(),
            Error::Invalid
        );
    }
    for key in ["tenant_id", "partition_class", "received_unix_millis"] {
        let mut value = serde_json::to_value(header()).unwrap();
        value.as_object_mut().unwrap().remove(key);
        assert_eq!(
            receive(&request(&serde_json::to_vec(&value).unwrap(), 0, b""))
                .await
                .unwrap_err(),
            Error::Invalid
        );
    }
}

#[tokio::test]
async fn noncanonical_uuid_digest_and_foreign_assignment_refuse() {
    let mut value = serde_json::to_value(header()).unwrap();
    for (field, replacement) in [
        ("tenant_id", header().tenant_id.to_string().to_uppercase()),
        ("tenant_id", header().tenant_id.simple().to_string()),
        ("source_id", Uuid::nil().to_string()),
        ("file_sha256", "A".repeat(64)),
        ("file_sha256", "0".repeat(63)),
    ] {
        let original = value[field].clone();
        value[field] = serde_json::Value::String(replacement);
        assert_eq!(
            receive(&request(&serde_json::to_vec(&value).unwrap(), 0, b""))
                .await
                .unwrap_err(),
            Error::Invalid
        );
        value[field] = original;
    }
    let wire = request(
        &serde_json::to_vec(&header()).unwrap(),
        BODY.len() as u64,
        BODY,
    );
    assert_eq!(
        read_request(
            &mut &wire[..],
            Uuid::from_u128(99),
            &ExchangeDeadline::new()
        )
        .await
        .unwrap_err(),
        Error::Mismatch
    );
}

#[tokio::test]
async fn typed_header_rejects_invalid_schema_counter_clock_route_and_partition() {
    for fault in 0..10 {
        let mut h = header();
        match fault {
            0 => h.schema_version = 2,
            1 => h.source_revision = 0,
            2 => h.credential_revision = 0,
            3 => h.credential_revision = MAX_CREDENTIAL_REVISION + 1,
            4 => h.received_unix_millis = 0,
            5 => h.received_unix_millis = u64::MAX,
            6 => h.route_key = "a".repeat(129),
            7 => h.route_key = "route/foreign".into(),
            8 => h.partition_class = Some(0),
            _ => h.partition_class = Some(999999),
        }
        assert_eq!(
            receive(&request(&serde_json::to_vec(&h).unwrap(), 0, b""))
                .await
                .unwrap_err(),
            Error::Invalid,
            "fault {fault}"
        );
    }
    let mut h = header();
    h.partition_class = Some(4001);
    h.credential_revision = MAX_CREDENTIAL_REVISION;
    assert!(h.validate().is_ok());
}

#[tokio::test]
async fn exact_input_digest_and_eof_are_required() {
    let json = serde_json::to_vec(&header()).unwrap();
    let mut corrupted = BODY.to_vec();
    corrupted[0] ^= 1;
    assert_eq!(
        receive(&request(&json, BODY.len() as u64, &corrupted))
            .await
            .unwrap_err(),
        Error::Mismatch
    );
    let mut extra = request(&json, BODY.len() as u64, BODY);
    extra.push(0);
    assert_eq!(receive(&extra).await.unwrap_err(), Error::Trailing);
}

#[tokio::test]
async fn response_binding_summary_counts_and_refusal_shape_are_checked_before_chunks() {
    for fault in 0..9 {
        let mut s = summary(binding());
        let expected = match fault {
            0 => {
                s.request_id += 1;
                Error::Mismatch
            }
            1 => {
                s.request_frame_sha256[0] ^= 1;
                Error::Mismatch
            }
            2 => {
                s.chunk_count = MAX_CHUNKS as u32 + 1;
                Error::Limit
            }
            3 => {
                s.rows_seen = MAX_ROWS + 1;
                Error::Limit
            }
            4 => {
                s.rows_seen += 1;
                Error::Mismatch
            }
            5 => {
                s.rows_time_clamped = 4;
                Error::Limit
            }
            6 => {
                s.rows_class_from_path = 5;
                Error::Limit
            }
            7 => {
                s.refusal_reason = Some(RefusalReason::Internal);
                Error::Mismatch
            }
            _ => {
                s.rows_accepted = 1;
                s.rows_refused = 3;
                Error::Mismatch
            }
        };
        let wire = response(&s, &[]);
        assert_eq!(
            read_response(&mut &wire[..], &binding(), &ExchangeDeadline::new())
                .await
                .unwrap_err(),
            expected,
            "fault {fault}"
        );
    }
}

#[tokio::test]
async fn response_chunk_limits_ordinals_and_declared_rows_precede_allocation() {
    let value = summary(binding());
    for (ordinal, length, events, expected) in [
        (1, 1, 1, Error::Mismatch),
        (0, 0, 1, Error::Limit),
        (0, MAX_CHUNK_BYTES as u32 + 1, 1, Error::Limit),
        (0, u32::MAX, 1, Error::Limit),
        (0, 1, 0, Error::Limit),
        (0, 1, MAX_CHUNK_ROWS + 1, Error::Limit),
        (0, 1, 4, Error::Mismatch),
    ] {
        let wire = response(&value, &[(ordinal, length, events, b"")]);
        assert_eq!(
            read_response(&mut &wire[..], &binding(), &ExchangeDeadline::new())
                .await
                .unwrap_err(),
            expected
        );
    }
    let wire = response(&value, &[(0, 2, 1, b"x")]);
    assert_eq!(
        read_response(&mut &wire[..], &binding(), &ExchangeDeadline::new())
            .await
            .unwrap_err(),
        Error::Truncated
    );
}

#[tokio::test]
async fn response_magic_summary_lengths_and_truncated_headers_refuse() {
    for (wire, expected) in [
        (b"NLR".to_vec(), Error::Truncated),
        (b"HTTP".to_vec(), Error::Invalid),
        (
            [b"NLR1".as_slice(), &0_u32.to_be_bytes()].concat(),
            Error::Limit,
        ),
        (
            [
                b"NLR1".as_slice(),
                &(MAX_METADATA_BYTES as u32 + 1).to_be_bytes(),
            ]
            .concat(),
            Error::Limit,
        ),
        (
            [b"NLR1".as_slice(), &100_u32.to_be_bytes(), b"{"].concat(),
            Error::Truncated,
        ),
    ] {
        assert_eq!(
            read_response(&mut &wire[..], &binding(), &ExchangeDeadline::new())
                .await
                .unwrap_err(),
            expected
        );
    }
}

#[tokio::test]
async fn response_unknown_duplicate_nullable_and_missing_fields_refuse() {
    let json = serde_json::to_string(&summary(binding())).unwrap();
    for prefix in [
        r#""native_key":"PRIVATE_CONTEXT_SENTINEL","#,
        r#""refusal_reason":null,"#,
        r#""rows_seen":4,"#,
    ] {
        let bad = format!("{{{prefix}{}", &json[1..]);
        let mut wire = b"NLR1".to_vec();
        wire.extend_from_slice(&(bad.len() as u32).to_be_bytes());
        wire.extend_from_slice(bad.as_bytes());
        assert_eq!(
            read_response(&mut &wire[..], &binding(), &ExchangeDeadline::new())
                .await
                .unwrap_err(),
            Error::Invalid
        );
    }
    for field in ["refusal_reason", "request_frame_sha256", "rows_seen"] {
        let mut value = serde_json::to_value(summary(binding())).unwrap();
        value.as_object_mut().unwrap().remove(field);
        let json = serde_json::to_vec(&value).unwrap();
        let mut wire = b"NLR1".to_vec();
        wire.extend_from_slice(&(json.len() as u32).to_be_bytes());
        wire.extend_from_slice(&json);
        assert_eq!(
            read_response(&mut &wire[..], &binding(), &ExchangeDeadline::new())
                .await
                .unwrap_err(),
            Error::Invalid
        );
    }
}

#[tokio::test]
async fn response_rejects_missing_rows_and_trailing_data_after_valid_frames() {
    let value = summary(binding());
    let mut wire = response(&value, &[(0, 1, 1, b"a"), (1, 1, 2, b"b")]);
    wire.push(0);
    assert_eq!(
        read_response(&mut &wire[..], &binding(), &ExchangeDeadline::new())
            .await
            .unwrap_err(),
        Error::Trailing
    );
    let wire = response(&value, &[(0, 1, 1, b"a"), (1, 1, 1, b"b")]);
    assert_eq!(
        read_response(&mut &wire[..], &binding(), &ExchangeDeadline::new())
            .await
            .unwrap_err(),
        Error::Mismatch
    );
}

#[derive(Default)]
struct NoWrites(usize);
impl AsyncWrite for NoWrites {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.0 += 1;
        Poll::Ready(Err(std::io::Error::new(
            ErrorKind::Other,
            "PRIVATE_IO_SENTINEL",
        )))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn invalid_writes_emit_no_partial_frame_and_transport_errors_do_not_retry() {
    let mut writer = NoWrites::default();
    let mut h = header();
    h.file_sha256[0] ^= 1;
    assert_eq!(
        write_request(&mut writer, &h, BODY, &ExchangeDeadline::new()).await,
        Err(Error::Mismatch)
    );
    assert_eq!(writer.0, 0);
    let bad = [ChunkRef {
        ordinal: 0,
        events: 1,
        bytes: b"a",
    }];
    assert_eq!(
        write_response(
            &mut writer,
            &summary(binding()),
            &bad,
            &ExchangeDeadline::new()
        )
        .await,
        Err(Error::Mismatch)
    );
    assert_eq!(writer.0, 0);
    assert_eq!(
        write_request(&mut writer, &header(), BODY, &ExchangeDeadline::new()).await,
        Err(Error::Io)
    );
    assert_eq!(writer.0, 1);
    assert!(!format!("{:?} {}", Error::Io, Error::Io).contains("PRIVATE_IO_SENTINEL"));
}

#[tokio::test]
async fn total_output_ceiling_is_checked_before_any_write() {
    let bytes = vec![0; MAX_CHUNK_BYTES];
    let parts = [
        ChunkRef {
            ordinal: 0,
            events: 1,
            bytes: &bytes,
        },
        ChunkRef {
            ordinal: 1,
            events: 1,
            bytes: &bytes,
        },
        ChunkRef {
            ordinal: 2,
            events: 1,
            bytes: b"a",
        },
    ];
    let mut value = summary(binding());
    value.chunk_count = 3;
    let mut writer = NoWrites::default();
    assert_eq!(
        write_response(&mut writer, &value, &parts, &ExchangeDeadline::new()).await,
        Err(Error::Limit)
    );
    assert_eq!(writer.0, 0);
}

#[tokio::test(start_paused = true)]
async fn one_absolute_deadline_does_not_restart_for_the_response() {
    let deadline = ExchangeDeadline::new();
    tokio::time::advance(Duration::from_secs(29)).await;
    let wire = request(
        &serde_json::to_vec(&header()).unwrap(),
        BODY.len() as u64,
        BODY,
    );
    assert!(
        read_request(&mut &wire[..], header().tenant_id, &deadline)
            .await
            .is_ok()
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(
        read_response(&mut &b""[..], &binding(), &deadline)
            .await
            .unwrap_err(),
        Error::Deadline
    );
}

#[tokio::test(start_paused = true)]
async fn pending_input_and_missing_eof_fail_at_the_whole_exchange_deadline() {
    let (mut writer, mut reader) = UnixStream::pair().unwrap();
    let wire = request(
        &serde_json::to_vec(&header()).unwrap(),
        BODY.len() as u64,
        BODY,
    );
    writer.write_all(&wire).await.unwrap();
    // A complete body without half-close is still incomplete transport.
    assert_eq!(
        read_request(&mut reader, header().tenant_id, &ExchangeDeadline::new())
            .await
            .unwrap_err(),
        Error::Deadline
    );
}

#[test]
fn debug_and_errors_never_echo_context_or_payloads() {
    let mut h = header();
    h.route_key = "PRIVATE_CONTEXT_SENTINEL".into();
    let request = ReceivedRequest {
        header: h.clone(),
        bytes: b"PRIVATE_BODY_SENTINEL".to_vec(),
        binding: binding(),
    };
    let output = UntrustedResponse {
        summary: summary(binding()),
        chunks: vec![OwnedChunk {
            ordinal: 0,
            events: 1,
            bytes: b"PRIVATE_BODY_SENTINEL".to_vec(),
        }],
        frame_sha256: [5; 32],
    };
    let text = format!(
        "{h:?} {request:?} {output:?} {:?} {:?}",
        output.chunks[0],
        binding()
    );
    assert!(!text.contains("PRIVATE_"));
    for error in [
        Error::Invalid,
        Error::Limit,
        Error::Mismatch,
        Error::Truncated,
        Error::Trailing,
        Error::Deadline,
        Error::Io,
    ] {
        assert!(!format!("{error:?} {error}").contains("PRIVATE_"));
    }
}
