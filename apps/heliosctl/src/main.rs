#[cfg(unix)]
use std::path::Path;
use std::{env, error::Error, net::SocketAddr, path::PathBuf};

use helios_config::load_token;
use helios_control::{
    CONTROL_VERSION, ControlCommand, ControlRequest, ControlResponse, read_message, write_message,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

type AnyError = Box<dyn Error + Send + Sync>;
trait ControlIo: AsyncRead + AsyncWrite + Unpin {}
impl<T: AsyncRead + AsyncWrite + Unpin> ControlIo for T {}
type ControlStream = Box<dyn ControlIo>;

enum ControlEndpoint {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(PathBuf),
    #[cfg(windows)]
    Pipe(String),
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), AnyError> {
    let (endpoint, token_file) = parse_args(env::args())?;
    let token = load_token(token_file)?;
    let mut stream = connect(endpoint).await?;
    write_message(
        &mut stream,
        &ControlRequest {
            version: CONTROL_VERSION,
            token,
            command: ControlCommand::GetStatus,
        },
    )
    .await?;
    let response: ControlResponse = read_message(&mut stream).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn parse_args(
    values: impl IntoIterator<Item = String>,
) -> Result<(ControlEndpoint, PathBuf), AnyError> {
    let values: Vec<String> = values.into_iter().collect();
    if values.len() != 4 || values[1] != "status" {
        return Err("usage: heliosctl status CONTROL_ENDPOINT TOKEN_FILE".into());
    }
    let endpoint = match values[2].parse() {
        Ok(address) => ControlEndpoint::Tcp(address),
        #[cfg(unix)]
        Err(_) if Path::new(&values[2]).is_absolute() => {
            ControlEndpoint::Unix(PathBuf::from(&values[2]))
        }
        #[cfg(windows)]
        Err(_) if values[2].starts_with(r"\.\pipe\") => ControlEndpoint::Pipe(values[2].clone()),
        Err(_) => {
            return Err(
                "control endpoint must be a socket address or absolute Unix socket path".into(),
            );
        }
    };
    Ok((endpoint, PathBuf::from(&values[3])))
}

async fn connect(endpoint: ControlEndpoint) -> std::io::Result<ControlStream> {
    match endpoint {
        ControlEndpoint::Tcp(address) => Ok(Box::new(TcpStream::connect(address).await?)),
        #[cfg(unix)]
        ControlEndpoint::Unix(path) => Ok(Box::new(tokio::net::UnixStream::connect(path).await?)),
        #[cfg(windows)]
        ControlEndpoint::Pipe(name) => Ok(Box::new(
            tokio::net::windows::named_pipe::ClientOptions::new().open(name)?,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp_control_endpoint() {
        let (endpoint, token) = parse_args([
            "heliosctl".into(),
            "status".into(),
            "127.0.0.1:9080".into(),
            "token.hex".into(),
        ])
        .unwrap();
        assert!(matches!(endpoint, ControlEndpoint::Tcp(_)));
        assert_eq!(token, PathBuf::from("token.hex"));
    }

    #[cfg(unix)]
    #[test]
    fn parses_absolute_unix_control_endpoint() {
        let (endpoint, _) = parse_args([
            "heliosctl".into(),
            "status".into(),
            "/tmp/helios.sock".into(),
            "token.hex".into(),
        ])
        .unwrap();
        assert!(matches!(endpoint, ControlEndpoint::Unix(_)));
    }
}
