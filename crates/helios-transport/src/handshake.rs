use helios_protocol::{
    Auth, AuthOk, CAP_PADDING_TIERS, ClientHello, DecodeError, EncodeError, Frame, FrameType,
    MAX_CONTROL_PAYLOAD, NONCE_LEN, SESSION_ID_LEN, ServerHello, compute_auth_proof,
    verify_auth_proof,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{FrameIo, FrameIoError};

const HELLO_REQUEST_ID: u32 = 1;
const AUTH_REQUEST_ID: u32 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedSession {
    pub session_id: [u8; SESSION_ID_LEN],
    pub capabilities: u32,
    pub max_control_payload: u32,
}

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error(transparent)]
    Frame(#[from] FrameIoError),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error("operating system random source failed: {0}")]
    Random(#[from] getrandom::Error),
    #[error("unexpected {actual:?} frame while expecting {expected:?}")]
    UnexpectedFrame {
        expected: FrameType,
        actual: FrameType,
    },
    #[error("response request ID does not match the handshake request")]
    RequestIdMismatch,
    #[error("authentication failed")]
    AuthenticationFailed,
}

pub async fn authenticate_client<S>(
    io: &mut FrameIo<S>,
    credential_id: &str,
    token: &[u8; 32],
    capabilities: u32,
) -> Result<AuthenticatedSession, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let capabilities = capabilities | CAP_PADDING_TIERS;
    let mut nonce = [0; NONCE_LEN];
    getrandom::fill(&mut nonce)?;
    let mut hello = ClientHello::new(nonce, capabilities, Vec::new())?;
    hello.padding = crate::padding::random_padding(hello.encode()?.len())?;
    let client_payload = hello.encode()?;
    io.write_frame(&Frame::new(
        FrameType::ClientHello,
        HELLO_REQUEST_ID,
        client_payload.clone(),
    )?)
    .await?;

    let server_frame = expect_frame(
        io.read_frame().await?,
        FrameType::ServerHello,
        HELLO_REQUEST_ID,
    )?;
    let server_hello = ServerHello::decode(&server_frame.payload)?;
    let proof = compute_auth_proof(token, &client_payload, &server_frame.payload);
    let mut auth = Auth::new(credential_id.to_owned(), proof, Vec::new())?;
    if server_hello.capabilities & capabilities & CAP_PADDING_TIERS != 0 {
        auth.padding = crate::padding::random_padding(auth.encode()?.len())?;
    }
    let auth_payload = auth.encode()?;
    io.write_frame(&Frame::new(FrameType::Auth, AUTH_REQUEST_ID, auth_payload)?)
        .await?;

    let response = io.read_frame().await?;
    if response.request_id != AUTH_REQUEST_ID {
        return Err(HandshakeError::RequestIdMismatch);
    }
    match response.frame_type {
        FrameType::AuthOk => {
            let auth_ok = AuthOk::decode(&response.payload)?;
            io.set_padding_negotiated(
                server_hello.capabilities & capabilities & CAP_PADDING_TIERS != 0,
            );
            Ok(AuthenticatedSession {
                session_id: auth_ok.session_id,
                capabilities: capabilities & server_hello.capabilities,
                max_control_payload: server_hello.max_control_payload,
            })
        }
        FrameType::AuthError => Err(HandshakeError::AuthenticationFailed),
        actual => Err(HandshakeError::UnexpectedFrame {
            expected: FrameType::AuthOk,
            actual,
        }),
    }
}

pub async fn authenticate_server<S, F>(
    io: &mut FrameIo<S>,
    capabilities: u32,
    resolve_token: F,
) -> Result<AuthenticatedSession, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&str) -> Option<[u8; 32]>,
{
    let capabilities = capabilities | CAP_PADDING_TIERS;
    let client_frame = expect_frame(
        io.read_frame().await?,
        FrameType::ClientHello,
        HELLO_REQUEST_ID,
    )?;
    let client_hello = ClientHello::decode(&client_frame.payload)?;

    let mut server_nonce = [0; NONCE_LEN];
    getrandom::fill(&mut server_nonce)?;
    let selected_capabilities = capabilities & client_hello.capabilities;
    let mut hello = ServerHello::new(
        server_nonce,
        selected_capabilities,
        MAX_CONTROL_PAYLOAD as u32,
        Vec::new(),
    )?;
    if selected_capabilities & CAP_PADDING_TIERS != 0 {
        hello.padding = crate::padding::random_padding(hello.encode()?.len())?;
    }
    let server_payload = hello.encode()?;
    io.write_frame(&Frame::new(
        FrameType::ServerHello,
        HELLO_REQUEST_ID,
        server_payload.clone(),
    )?)
    .await?;

    let auth_frame = expect_frame(io.read_frame().await?, FrameType::Auth, AUTH_REQUEST_ID)?;
    let auth = Auth::decode(&auth_frame.payload)?;
    let valid = resolve_token(&auth.credential_id).is_some_and(|token| {
        verify_auth_proof(&token, &client_frame.payload, &server_payload, &auth.proof)
    });
    if !valid {
        io.write_frame(&Frame::new(
            FrameType::AuthError,
            AUTH_REQUEST_ID,
            Vec::new(),
        )?)
        .await?;
        return Err(HandshakeError::AuthenticationFailed);
    }

    let mut session_id = [0; SESSION_ID_LEN];
    getrandom::fill(&mut session_id)?;
    io.write_frame(&Frame::new(
        FrameType::AuthOk,
        AUTH_REQUEST_ID,
        AuthOk { session_id }.encode().to_vec(),
    )?)
    .await?;
    io.set_padding_negotiated(selected_capabilities & CAP_PADDING_TIERS != 0);
    Ok(AuthenticatedSession {
        session_id,
        capabilities: selected_capabilities,
        max_control_payload: MAX_CONTROL_PAYLOAD as u32,
    })
}

fn expect_frame(
    frame: Frame,
    expected: FrameType,
    request_id: u32,
) -> Result<Frame, HandshakeError> {
    if frame.request_id != request_id {
        return Err(HandshakeError::RequestIdMismatch);
    }
    if frame.frame_type != expected {
        return Err(HandshakeError::UnexpectedFrame {
            expected,
            actual: frame.frame_type,
        });
    }
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use helios_protocol::CAP_TCP_CONNECT;
    use tokio::io::duplex;

    use super::*;

    #[tokio::test]
    async fn new_client_authenticates_with_legacy_server_without_padding_capability() {
        let (client, server) = duplex(4096);
        let token = [7; 32];
        let peer = tokio::spawn(async move {
            let mut io = FrameIo::new(server);
            let client = io.read_frame().await.unwrap();
            assert!(
                !ClientHello::decode(&client.payload)
                    .unwrap()
                    .padding
                    .is_empty()
            );
            let hello = ServerHello::new(
                [3; NONCE_LEN],
                CAP_TCP_CONNECT,
                MAX_CONTROL_PAYLOAD as u32,
                vec![],
            )
            .unwrap()
            .encode()
            .unwrap();
            io.write_frame(
                &Frame::new(FrameType::ServerHello, HELLO_REQUEST_ID, hello.clone()).unwrap(),
            )
            .await
            .unwrap();
            let frame = io.read_frame().await.unwrap();
            let auth = Auth::decode(&frame.payload).unwrap();
            assert!(auth.padding.is_empty());
            assert!(verify_auth_proof(
                &token,
                &client.payload,
                &hello,
                &auth.proof
            ));
            io.write_frame(
                &Frame::new(
                    FrameType::AuthOk,
                    AUTH_REQUEST_ID,
                    AuthOk {
                        session_id: [1; SESSION_ID_LEN],
                    }
                    .encode()
                    .to_vec(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        });
        let mut io = FrameIo::new(client);
        let session = authenticate_client(&mut io, "test", &token, CAP_TCP_CONNECT)
            .await
            .unwrap();
        assert_eq!(session.capabilities, CAP_TCP_CONNECT);
        assert!(!io.padding_negotiated());
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn new_server_authenticates_legacy_client_without_padding() {
        let (client, server) = duplex(4096);
        let token = [7; 32];
        let peer = tokio::spawn(async move {
            let mut io = FrameIo::new(server);
            let session = authenticate_server(&mut io, CAP_TCP_CONNECT, |_| Some(token))
                .await
                .unwrap();
            assert_eq!(session.capabilities, CAP_TCP_CONNECT);
            assert!(!io.padding_negotiated());
        });
        let mut io = FrameIo::new(client);
        let hello = ClientHello::new([4; NONCE_LEN], CAP_TCP_CONNECT, vec![])
            .unwrap()
            .encode()
            .unwrap();
        io.write_frame(
            &Frame::new(FrameType::ClientHello, HELLO_REQUEST_ID, hello.clone()).unwrap(),
        )
        .await
        .unwrap();
        let server = io.read_frame().await.unwrap();
        let decoded = ServerHello::decode(&server.payload).unwrap();
        assert!(decoded.padding.is_empty());
        let auth = Auth::new(
            "test".into(),
            compute_auth_proof(&token, &hello, &server.payload),
            vec![],
        )
        .unwrap();
        io.write_frame(
            &Frame::new(FrameType::Auth, AUTH_REQUEST_ID, auth.encode().unwrap()).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(io.read_frame().await.unwrap().frame_type, FrameType::AuthOk);
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn authenticates_matching_credentials() {
        let token = [7; 32];
        let (client_stream, server_stream) = duplex(4096);
        let server = tokio::spawn(async move {
            let mut io = FrameIo::new(server_stream);
            authenticate_server(&mut io, CAP_TCP_CONNECT, |id| {
                (id == "desktop-main").then_some(token)
            })
            .await
            .unwrap()
        });

        let mut io = FrameIo::new(client_stream);
        let client_session = authenticate_client(&mut io, "desktop-main", &token, CAP_TCP_CONNECT)
            .await
            .unwrap();
        let server_session = server.await.unwrap();

        assert_eq!(client_session, server_session);
        assert_eq!(
            client_session.capabilities,
            CAP_TCP_CONNECT | CAP_PADDING_TIERS
        );
        assert!(io.padding_negotiated());
    }

    #[tokio::test]
    async fn rejects_wrong_token_with_generic_auth_error() {
        let server_token = [7; 32];
        let (client_stream, server_stream) = duplex(4096);
        let server = tokio::spawn(async move {
            let mut io = FrameIo::new(server_stream);
            authenticate_server(&mut io, CAP_TCP_CONNECT, |_| Some(server_token)).await
        });

        let mut io = FrameIo::new(client_stream);
        let client_result =
            authenticate_client(&mut io, "desktop-main", &[8; 32], CAP_TCP_CONNECT).await;
        let server_result = server.await.unwrap();

        assert!(matches!(
            client_result,
            Err(HandshakeError::AuthenticationFailed)
        ));
        assert!(matches!(
            server_result,
            Err(HandshakeError::AuthenticationFailed)
        ));
    }

    #[tokio::test]
    async fn rejects_unknown_credential_without_distinguishing_it() {
        let (client_stream, server_stream) = duplex(4096);
        let server = tokio::spawn(async move {
            let mut io = FrameIo::new(server_stream);
            authenticate_server(&mut io, CAP_TCP_CONNECT, |_| None).await
        });

        let mut io = FrameIo::new(client_stream);
        let client_result =
            authenticate_client(&mut io, "unknown", &[8; 32], CAP_TCP_CONNECT).await;
        let server_result = server.await.unwrap();

        assert!(matches!(
            client_result,
            Err(HandshakeError::AuthenticationFailed)
        ));
        assert!(matches!(
            server_result,
            Err(HandshakeError::AuthenticationFailed)
        ));
    }
}
