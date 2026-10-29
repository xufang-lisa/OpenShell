// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cancellation-safe capture of the first explicit/virtual proxy envelope.

use crate::l7::session::RequestSlot;
use miette::{IntoDiagnostic, Result};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

#[derive(Debug, PartialEq, Eq)]
pub(super) enum HeaderCapture {
    Complete,
    Closed,
    TooLarge,
}

/// Both reader and slot must outlive this borrowed future. Do not consume
/// bytes behind the header: they belong to the body or inner CONNECT stream.
pub(super) async fn capture_proxy_header<C: AsyncRead + Unpin>(
    client: &mut BufReader<C>,
    slot: &mut RequestSlot,
) -> Result<HeaderCapture> {
    let buffer = slot.capture_buffer()?;
    loop {
        if buffer.ends_with(b"\r\n\r\n") {
            return Ok(HeaderCapture::Complete);
        }
        if buffer.len() >= super::MAX_HEADER_BYTES {
            return Ok(HeaderCapture::TooLarge);
        }
        let available = client.fill_buf().await.into_diagnostic()?;
        if available.is_empty() {
            return Ok(HeaderCapture::Closed);
        }
        let previous = buffer.len();
        let count = available.len().min(super::MAX_HEADER_BYTES - previous);
        buffer.extend_from_slice(&available[..count]);
        let start = previous.saturating_sub(3);
        let end = buffer[start..]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| start + position + 4);
        let consumed = end.map_or(count, |end| end - previous);
        // No await between saving the prefix and consuming the same bytes.
        client.consume(consumed);
        buffer.truncate(previous + consumed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::poll;
    use tokio::io::AsyncWriteExt;

    const HEADER: &[u8] =
        b"GET http://example.com/a/../missing?mode=safe HTTP/1.1\r\nHost: example.com\r\n\r\n";

    #[tokio::test]
    async fn every_partial_boundary_survives_cancel_and_keeps_read_ahead() {
        for boundary in 0..HEADER.len() {
            let (mut wire, client) = tokio::io::duplex(16 * 1024);
            let mut reader = BufReader::new(client);
            let mut slot = RequestSlot::new();
            wire.write_all(&HEADER[..boundary]).await.unwrap();
            {
                let capture = capture_proxy_header(&mut reader, &mut slot);
                tokio::pin!(capture);
                assert!(poll!(capture.as_mut()).is_pending());
            }
            assert_eq!(slot.partial_header(), &HEADER[..boundary]);
            wire.write_all(&[&HEADER[boundary..], b"next-input"].concat())
                .await
                .unwrap();
            assert_eq!(
                capture_proxy_header(&mut reader, &mut slot).await.unwrap(),
                HeaderCapture::Complete
            );
            assert_eq!(slot.partial_header(), HEADER);
            assert_eq!(reader.buffer(), b"next-input");
            let storage = slot.partial_header().as_ptr();
            let header = slot.take_dispatch_header().unwrap();
            assert_eq!(header, HEADER);
            assert_eq!(header.as_ptr(), storage);
            assert!(slot.partial_header().is_empty());
        }
    }

    #[tokio::test]
    async fn connect_envelope_leaves_inner_tls_bytes_in_original_reader() {
        let (mut wire, client) = tokio::io::duplex(8192);
        let mut reader = BufReader::new(client);
        let mut slot = RequestSlot::new();
        let header = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let tls = b"\x16\x03\x01inner-tls-record";
        wire.write_all(&[header.as_slice(), tls.as_slice()].concat())
            .await
            .unwrap();
        assert_eq!(
            capture_proxy_header(&mut reader, &mut slot).await.unwrap(),
            HeaderCapture::Complete
        );
        assert_eq!(slot.take_dispatch_header().unwrap(), header);
        assert_eq!(reader.buffer(), tls);
    }

    #[tokio::test]
    async fn eof_size_limit_and_terminal_do_not_create_a_complete_request() {
        for bytes in [b"GET /partial".as_slice(), b"".as_slice()] {
            let (mut wire, client) = tokio::io::duplex(8192);
            wire.write_all(bytes).await.unwrap();
            wire.shutdown().await.unwrap();
            let mut reader = BufReader::new(client);
            let mut slot = RequestSlot::new();
            assert_eq!(
                capture_proxy_header(&mut reader, &mut slot).await.unwrap(),
                HeaderCapture::Closed
            );
            assert_eq!(slot.partial_header(), bytes);
            assert!(slot.take_dispatch_header().is_err());
            slot.terminate();
            assert!(capture_proxy_header(&mut reader, &mut slot).await.is_err());
        }
        let (mut wire, client) = tokio::io::duplex(16 * 1024);
        wire.write_all(&vec![b'x'; super::super::MAX_HEADER_BYTES])
            .await
            .unwrap();
        let mut reader = BufReader::new(client);
        let mut slot = RequestSlot::new();
        assert_eq!(
            capture_proxy_header(&mut reader, &mut slot).await.unwrap(),
            HeaderCapture::TooLarge
        );
        assert!(slot.take_dispatch_header().is_err());
    }
}
