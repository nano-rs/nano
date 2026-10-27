// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use sha2_10::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const REQUEST_MAGIC: &[u8; 4] = b"NLB1";
const RESPONSE_MAGIC: &[u8; 4] = b"NLR1";
const REQUEST_DOMAIN: &[u8] = b"nano-landing-request-v1\0";
const RESPONSE_DOMAIN: &[u8] = b"nano-landing-response-v1\0";

fn io_error(error: std::io::Error) -> Error {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        Error::Truncated
    } else {
        Error::Io
    }
}
fn hash(domain: &[u8]) -> Sha256 {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash
}
fn allocation(length: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| Error::Limit)?;
    bytes.resize(length, 0);
    Ok(bytes)
}
async fn read_array<R: AsyncRead + Unpin, const N: usize>(
    reader: &mut R,
    hash: &mut Sha256,
) -> Result<[u8; N], Error> {
    let mut bytes = [0; N];
    reader.read_exact(&mut bytes).await.map_err(io_error)?;
    hash.update(bytes);
    Ok(bytes)
}
async fn read_bytes<R: AsyncRead + Unpin>(
    reader: &mut R,
    hash: &mut Sha256,
    length: usize,
) -> Result<Vec<u8>, Error> {
    let mut bytes = allocation(length)?;
    reader.read_exact(&mut bytes).await.map_err(io_error)?;
    hash.update(&bytes);
    Ok(bytes)
}
async fn write_bytes<W: AsyncWrite + Unpin>(
    writer: &mut W,
    hash: &mut Sha256,
    bytes: &[u8],
) -> Result<(), Error> {
    writer.write_all(bytes).await.map_err(io_error)?;
    hash.update(bytes);
    Ok(())
}
async fn eof<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(), Error> {
    let mut extra = [0];
    match reader.read(&mut extra).await.map_err(io_error)? {
        0 => Ok(()),
        _ => Err(Error::Trailing),
    }
}
async fn close<W: AsyncWrite + Unpin>(writer: &mut W) -> Result<(), Error> {
    writer.flush().await.map_err(io_error)?;
    writer.shutdown().await.map_err(io_error)
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::Invalid)?;
    if bytes.is_empty() || bytes.len() > MAX_METADATA_BYTES {
        return Err(Error::Limit);
    }
    Ok(bytes)
}
async fn metadata<R: AsyncRead + Unpin, T: for<'de> Deserialize<'de>>(
    reader: &mut R,
    hash: &mut Sha256,
) -> Result<T, Error> {
    let length = u32::from_be_bytes(read_array(reader, hash).await?) as usize;
    if length == 0 || length > MAX_METADATA_BYTES {
        return Err(Error::Limit);
    }
    serde_json::from_slice(&read_bytes(reader, hash, length).await?).map_err(|_| Error::Invalid)
}

pub async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    header: &RequestHeader,
    body: &[u8],
    deadline: &ExchangeDeadline,
) -> Result<RequestBinding, Error> {
    deadline
        .run(async {
            header.validate()?;
            if body.is_empty() || body.len() > MAX_INPUT_BYTES {
                return Err(Error::Limit);
            }
            let actual: [u8; 32] = Sha256::digest(body).into();
            if actual != header.file_sha256 {
                return Err(Error::Mismatch);
            }
            let encoded = encode(header)?;
            let mut hash = hash(REQUEST_DOMAIN);
            write_bytes(writer, &mut hash, REQUEST_MAGIC).await?;
            write_bytes(writer, &mut hash, &(encoded.len() as u32).to_be_bytes()).await?;
            write_bytes(writer, &mut hash, &encoded).await?;
            write_bytes(writer, &mut hash, &(body.len() as u64).to_be_bytes()).await?;
            write_bytes(writer, &mut hash, body).await?;
            close(writer).await?;
            Ok(RequestBinding {
                request_id: header.request_id,
                frame_sha256: hash.finalize().into(),
            })
        })
        .await
}

pub async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut R,
    expected_tenant: Uuid,
    deadline: &ExchangeDeadline,
) -> Result<ReceivedRequest, Error> {
    deadline
        .run(async {
            if expected_tenant.is_nil() {
                return Err(Error::Invalid);
            }
            let mut hash = hash(REQUEST_DOMAIN);
            if &read_array::<R, 4>(reader, &mut hash).await? != REQUEST_MAGIC {
                return Err(Error::Invalid);
            }
            let header: RequestHeader = metadata(reader, &mut hash).await?;
            header.validate()?;
            if header.tenant_id != expected_tenant {
                return Err(Error::Mismatch);
            }
            let length = u64::from_be_bytes(read_array(reader, &mut hash).await?);
            if length == 0 || length > MAX_INPUT_BYTES as u64 {
                return Err(Error::Limit);
            }
            let bytes = read_bytes(reader, &mut hash, length as usize).await?;
            let actual: [u8; 32] = Sha256::digest(&bytes).into();
            if actual != header.file_sha256 {
                return Err(Error::Mismatch);
            }
            eof(reader).await?;
            let binding = RequestBinding {
                request_id: header.request_id,
                frame_sha256: hash.finalize().into(),
            };
            Ok(ReceivedRequest {
                header,
                bytes,
                binding,
            })
        })
        .await
}

fn chunk(
    ordinal: u32,
    expected: usize,
    length: usize,
    events: u64,
    total: &mut (usize, u64),
) -> Result<(), Error> {
    if ordinal as usize != expected {
        return Err(Error::Mismatch);
    }
    if length == 0 || length > MAX_CHUNK_BYTES || !(1..=MAX_CHUNK_ROWS).contains(&events) {
        return Err(Error::Limit);
    }
    let bytes = total.0.checked_add(length).ok_or(Error::Limit)?;
    let rows = total.1.checked_add(events).ok_or(Error::Limit)?;
    if bytes > MAX_OUTPUT_BYTES || rows > MAX_ROWS {
        return Err(Error::Limit);
    }
    *total = (bytes, rows);
    Ok(())
}

pub async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    summary: &ResponseSummary,
    chunks: &[ChunkRef<'_>],
    deadline: &ExchangeDeadline,
) -> Result<[u8; 32], Error> {
    deadline
        .run(async {
            summary.validate()?;
            if chunks.len() != summary.chunk_count as usize {
                return Err(Error::Mismatch);
            }
            let mut total = (0, 0);
            for (index, part) in chunks.iter().enumerate() {
                chunk(
                    part.ordinal,
                    index,
                    part.bytes.len(),
                    part.events,
                    &mut total,
                )?;
            }
            if total.1 != summary.rows_accepted {
                return Err(Error::Mismatch);
            }
            let encoded = encode(summary)?;
            let mut hash = hash(RESPONSE_DOMAIN);
            write_bytes(writer, &mut hash, RESPONSE_MAGIC).await?;
            write_bytes(writer, &mut hash, &(encoded.len() as u32).to_be_bytes()).await?;
            write_bytes(writer, &mut hash, &encoded).await?;
            for part in chunks {
                write_bytes(writer, &mut hash, &part.ordinal.to_be_bytes()).await?;
                write_bytes(writer, &mut hash, &(part.bytes.len() as u32).to_be_bytes()).await?;
                write_bytes(writer, &mut hash, &part.events.to_be_bytes()).await?;
                write_bytes(writer, &mut hash, part.bytes).await?;
            }
            close(writer).await?;
            Ok(hash.finalize().into())
        })
        .await
}

pub async fn read_response<R: AsyncRead + Unpin>(
    reader: &mut R,
    expected: &RequestBinding,
    deadline: &ExchangeDeadline,
) -> Result<UntrustedResponse, Error> {
    deadline
        .run(async {
            let mut hash = hash(RESPONSE_DOMAIN);
            if &read_array::<R, 4>(reader, &mut hash).await? != RESPONSE_MAGIC {
                return Err(Error::Invalid);
            }
            let summary: ResponseSummary = metadata(reader, &mut hash).await?;
            summary.validate()?;
            if summary.request_id != expected.request_id
                || summary.request_frame_sha256 != expected.frame_sha256
            {
                return Err(Error::Mismatch);
            }
            let mut chunks = Vec::new();
            chunks
                .try_reserve_exact(summary.chunk_count as usize)
                .map_err(|_| Error::Limit)?;
            let mut total = (0, 0);
            for index in 0..summary.chunk_count as usize {
                let ordinal = u32::from_be_bytes(read_array(reader, &mut hash).await?);
                let length = u32::from_be_bytes(read_array(reader, &mut hash).await?) as usize;
                let events = u64::from_be_bytes(read_array(reader, &mut hash).await?);
                // Validate totals and ordinals BEFORE allocating or reading a body.
                chunk(ordinal, index, length, events, &mut total)?;
                if total.1 > summary.rows_accepted {
                    return Err(Error::Mismatch);
                }
                let bytes = read_bytes(reader, &mut hash, length).await?;
                chunks.push(OwnedChunk {
                    ordinal,
                    events,
                    bytes,
                });
            }
            if total.1 != summary.rows_accepted {
                return Err(Error::Mismatch);
            }
            eof(reader).await?;
            Ok(UntrustedResponse {
                summary,
                chunks,
                frame_sha256: hash.finalize().into(),
            })
        })
        .await
}
