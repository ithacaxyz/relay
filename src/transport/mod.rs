//! L2 Transport implementation with `eth_sendRawTransaction` forwarding.

use alloy::{
    rpc::json_rpc::{RequestPacket, Response, ResponsePacket},
    transports::{Transport, TransportError, TransportErrorKind, TransportFut},
};
use std::task::{Context, Poll, ready};
use tower::Service;

pub mod error;

const ETH_SEND_RAW_TRANSACTION: &str = "eth_sendRawTransaction";

/// A [`alloy::transports::Transport`] that combines two transports.
/// And also forwards requests for `eth_sendRawTransaction` to the sequencer service.
///
/// This exclusively forwards `eth_sendRawTransaction` because it is assumed that this is the only
/// endpoint that is whitelisted by the sequencer server.
#[derive(Debug, Clone)]
pub struct SequencerService<T, S> {
    /// The regular transport
    inner: T,
    /// The transport to route requests to the sequencer.
    sequencer: S,
}

impl<T, S> SequencerService<T, S> {
    /// Creates a new instance of the [`SequencerService`].
    pub const fn new(inner: T, sequencer: S) -> SequencerService<T, S> {
        SequencerService { sequencer, inner }
    }

    /// Configures the regular transport
    pub fn with_transport<U>(self, inner: U) -> SequencerService<U, S> {
        SequencerService { sequencer: self.sequencer, inner }
    }

    /// Configures the regular transport
    pub fn with_sequencer<U>(self, sequencer: U) -> SequencerService<T, U> {
        SequencerService { inner: self.inner, sequencer }
    }
}

impl Default for SequencerService<(), ()> {
    fn default() -> Self {
        Self { sequencer: (), inner: () }
    }
}

impl<T, S> Service<RequestPacket> for SequencerService<T, S>
where
    T: Transport,
    S: Transport,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Both services must be ready
        ready!(self.inner.poll_ready(cx))?;
        self.sequencer.poll_ready(cx)
    }

    fn call(&mut self, req: RequestPacket) -> Self::Future {
        use alloy::rpc::json_rpc::ResponsePayload::*;

        // TODO: simplify after <https://github.com/alloy-rs/alloy/pull/2304>
        if let RequestPacket::Single(r) = &req {
            if r.method() == ETH_SEND_RAW_TRANSACTION {
                // This is raw transaction submission that we want to also route to the sequencer
                let to_sequencer = self.sequencer.call(r.clone().into());
                let to_inner = self.inner.call(req);
                return Box::pin(async move {
                    let (ResponsePacket::Single(seq), ResponsePacket::Single(inner)) =
                        futures_util::future::try_join(to_sequencer, to_inner).await?
                    else {
                        return Err(TransportErrorKind::custom_str("unexpected response"));
                    };

                    if seq.payload.is_success() {
                        return Ok(ResponsePacket::Single(seq));
                    }

                    let id = seq.id;

                    // Handle potential errors. We are not treating "already known" as fatal if at
                    // least one of the endpoints accepted the transaction
                    let payload = match (seq.payload, inner.payload) {
                        (Success(seq), _) => Success(seq),
                        (Failure(seq), Success(inner)) => {
                            if seq.message == "already known" {
                                Success(inner)
                            } else {
                                Failure(seq)
                            }
                        }
                        (Failure(seq), Failure(inner)) => {
                            if seq.message == "already known" {
                                Failure(inner)
                            } else {
                                Failure(seq)
                            }
                        }
                    };

                    Ok(ResponsePacket::Single(Response { payload, id }))
                });
            }
        }

        self.inner.call(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        primitives::B256,
        rpc::json_rpc::{Id, Request, Response, ResponsePayload, SerializedRequest},
    };
    use serde_json::value::RawValue;
    use std::future::poll_fn;

    /// Helper function that transforms a closure to a alloy transport service
    fn request_fn<T>(f: T) -> RequestFn<T>
    where
        T: FnMut(RequestPacket) -> TransportFut<'static>,
    {
        RequestFn { f }
    }

    #[derive(Copy, Clone)]
    struct RequestFn<T> {
        f: T,
    }

    impl<T> Service<RequestPacket> for RequestFn<T>
    where
        T: FnMut(RequestPacket) -> TransportFut<'static>,
    {
        type Response = ResponsePacket;
        type Error = TransportError;
        type Future = TransportFut<'static>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), TransportError>> {
            Ok(()).into()
        }

        fn call(&mut self, req: RequestPacket) -> Self::Future {
            (self.f)(req)
        }
    }

    fn make_hash_response() -> ResponsePacket {
        ResponsePacket::Single(Response {
            id: Id::Number(0),
            payload: ResponsePayload::Success(
                RawValue::from_string(serde_json::to_string(&B256::ZERO).unwrap()).unwrap(),
            ),
        })
    }

    #[tokio::test]
    async fn test_raw_tx_forwarding_service() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let sequencer_transport = request_fn(move |request: RequestPacket| {
            let tx = tx.clone();
            Box::pin(async move {
                tx.send(request).unwrap();
                Ok::<_, TransportError>(make_hash_response())
            })
        });

        let regular_transport = request_fn(|_request: RequestPacket| {
            Box::pin(async move { Ok::<_, TransportError>(make_hash_response()) })
        });

        let mut service = SequencerService::default()
            .with_transport(regular_transport)
            .with_sequencer(sequencer_transport);

        let request = Request::new(ETH_SEND_RAW_TRANSACTION, Id::Number(0), ("0x00".to_string(),));
        let packet = RequestPacket::from(SerializedRequest::try_from(request).unwrap());

        let _resp = service.call(packet).await.unwrap();

        // received raw tx request through sequencer transport
        let _ = rx.recv().await.unwrap();

        let request = Request::new("not_raw", Id::Number(0), ("0x00".to_string(),));
        let packet = RequestPacket::from(SerializedRequest::try_from(request).unwrap());

        let _resp = service.call(packet).await.unwrap();

        poll_fn(|cx| {
            assert!(rx.poll_recv(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }
}
