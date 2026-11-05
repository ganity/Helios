use std::{
    env,
    error::Error,
    fs::File,
    io::{BufReader, Error as IoError, ErrorKind},
    net::{IpAddr, SocketAddr},
    path::Path,
};

use helios_protocol::{Address, CAP_TCP_CONNECT, ConnectTcp, Target};
use helios_transport::{
    ClientCrypto, FrameIo, QuicBiStream, authenticate_client, client_quic_endpoint, open_tcp,
};
use rustls::{RootCertStore, pki_types::ServerName};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

mod desktop;
mod i18n;

type AnyError = Box<dyn Error + Send + Sync>;

#[derive(Clone, Copy)]
enum TransportKind {
    Quic,
    Tls,
}

struct Args {
    transport: TransportKind,
    server: SocketAddr,
    server_name: String,
    ca_certificate: String,
    credential_id: String,
    token: [u8; 32],
    target: Target,
}

fn main() -> Result<(), AnyError> {
    if env::args().len() == 1 {
        return desktop::run();
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run_cli())
}

async fn run_cli() -> Result<(), AnyError> {
    let args = parse_args()?;
    let roots = load_roots(&args.ca_certificate)?;
    let crypto = ClientCrypto::new(roots)?;

    match args.transport {
        TransportKind::Tls => run_tls(args, crypto).await,
        TransportKind::Quic => run_quic(args, crypto).await,
    }
}

async fn run_tls(args: Args, crypto: ClientCrypto) -> Result<(), AnyError> {
    let tcp = TcpStream::connect(args.server).await?;
    let server_name = ServerName::try_from(args.server_name.clone())?;
    let mut io = crypto.tls.connect(server_name, tcp).await?;
    authenticate_client(&mut io, &args.credential_id, &args.token, CAP_TCP_CONNECT).await?;
    let request = ConnectTcp::new(args.target, 10_000, Vec::new())?;
    let stream = open_tcp(io, 3, &request).await?;
    relay_stdio(stream).await?;
    Ok(())
}

async fn run_quic(args: Args, crypto: ClientCrypto) -> Result<(), AnyError> {
    let mut endpoint = client_quic_endpoint(args.server)?;
    endpoint.set_default_client_config(crypto.quic);
    let connection = endpoint.connect(args.server, &args.server_name)?.await?;

    let (send, recv) = connection.open_bi().await?;
    let mut control = FrameIo::new(QuicBiStream::new(send, recv));
    authenticate_client(
        &mut control,
        &args.credential_id,
        &args.token,
        CAP_TCP_CONNECT,
    )
    .await?;

    let (send, recv) = connection.open_bi().await?;
    let mut io = FrameIo::new(QuicBiStream::new(send, recv));
    io.set_padding_negotiated(control.padding_negotiated());
    let request = ConnectTcp::new(args.target, 10_000, Vec::new())?;
    let stream = open_tcp(io, 3, &request).await?;
    relay_stdio(stream).await?;
    connection.close(0u32.into(), b"client complete");
    endpoint.wait_idle().await;
    Ok(())
}

async fn relay_stdio<S>(stream: S) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let upload = async {
        tokio::io::copy(&mut tokio::io::stdin(), &mut writer).await?;
        writer.shutdown().await
    };
    let download = async {
        let mut stdout = tokio::io::stdout();
        tokio::io::copy(&mut reader, &mut stdout).await?;
        stdout.flush().await
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}

fn parse_args() -> Result<Args, AnyError> {
    let values: Vec<String> = env::args().collect();
    if values.len() != 9 {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            "usage: helios-client TRANSPORT SERVER_ADDR SERVER_NAME CA_PEM CREDENTIAL_ID TOKEN_FILE TARGET_HOST TARGET_PORT",
        )
        .into());
    }
    let transport = match values[1].as_str() {
        "quic" => TransportKind::Quic,
        "tls" => TransportKind::Tls,
        _ => {
            return Err(
                IoError::new(ErrorKind::InvalidInput, "TRANSPORT must be quic or tls").into(),
            );
        }
    };
    let target_address = match values[7].parse::<IpAddr>() {
        Ok(ip) => Address::Ip(ip),
        Err(_) => Address::Domain(values[7].clone()),
    };
    Ok(Args {
        transport,
        server: values[2].parse()?,
        server_name: values[3].clone(),
        ca_certificate: values[4].clone(),
        credential_id: values[5].clone(),
        token: load_token(&values[6])?,
        target: Target::new(target_address, values[8].parse()?)?,
    })
}

fn load_roots(path: impl AsRef<Path>) -> Result<RootCertStore, AnyError> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut roots = RootCertStore::empty();
    let mut count = 0;
    for certificate in rustls_pemfile::certs(&mut reader) {
        roots.add(certificate?)?;
        count += 1;
    }
    if count == 0 {
        return Err(IoError::new(ErrorKind::InvalidData, "CA certificate file is empty").into());
    }
    Ok(roots)
}

fn parse_token(value: &str) -> Result<[u8; 32], AnyError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            "TOKEN_HEX must contain exactly 64 hexadecimal characters",
        )
        .into());
    }
    let mut token = [0; 32];
    for (index, byte) in token.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(token)
}

fn load_token(path: impl AsRef<Path>) -> Result<[u8; 32], AnyError> {
    parse_token(std::fs::read_to_string(path)?.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_token() {
        let token = parse_token(&"07".repeat(32)).unwrap();
        assert_eq!(token, [7; 32]);
        assert!(parse_token("07").is_err());
        assert!(parse_token(&"zz".repeat(32)).is_err());
    }
}
