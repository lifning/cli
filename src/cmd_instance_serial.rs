use std::os::unix::io::AsRawFd;
use std::time::Duration;
use anyhow::Result;
use futures::{SinkExt, StreamExt};
use http::HeaderMap;
use reqwest::ClientBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::protocol::{Message, Role};
use tokio_tungstenite::WebSocketStream;

mod nexus_client {
    progenitor::generate_api!(
        spec = "spec-serial.json",
        interface = Builder,
    );
}

impl crate::cmd_instance::CmdInstanceSerial {
    pub(crate) async fn websock_stream_tty(&self, client: oxide_api::Client) -> Result<()> {
        let reqw = client.request_raw(http::Method::GET, "", None)
            .await?
            .build()?;

        let base = reqw.url().as_str();
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            reqw.headers().get(http::header::AUTHORIZATION)
                .unwrap()
                .to_owned()
        );

        let reqw_client = ClientBuilder::new()
            .connect_timeout(Duration::new(60, 0))
            .default_headers(headers)
            .build()?;

        let nexus_client = nexus_client::Client::new_with_client(base, reqw_client);

        let upgraded = nexus_client
            .instance_serial_console_stream()
            .organization_name(self.organization.to_owned())
            .project_name(self.project.to_owned())
            .instance_name(self.instance.to_owned())
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?
            .into_inner();

        let mut ws = WebSocketStream::from_raw_socket(upgraded, Role::Client, None).await;

        let _raw_guard = RawTermiosGuard::stdio_guard()
            .expect("failed to set raw mode");

        let mut stdout = tokio::io::stdout();

        // https://docs.rs/tokio/latest/tokio/io/trait.AsyncReadExt.html#method.read_exact
        // is not cancel safe! Meaning reads from tokio::io::stdin are not cancel
        // safe. Spawn a separate task to read and put bytes onto this channel.
        let (stdintx, stdinrx) = tokio::sync::mpsc::channel(16);
        let (wstx, mut wsrx) = tokio::sync::mpsc::channel(16);

        tokio::spawn(async move {
            let mut stdin = tokio::io::stdin();
            let mut inbuf = [0u8; 1024];

            loop {
                let n = match stdin.read(&mut inbuf).await {
                    Err(_) | Ok(0) => break,
                    Ok(n) => n,
                };

                stdintx.send(inbuf[0..n].to_vec()).await.unwrap();
            }
        });

        tokio::spawn(async move { stdin_to_websockets_task(stdinrx, wstx).await });

        loop {
            tokio::select! {
                c = wsrx.recv() => {
                    match c {
                        None => {
                            // channel is closed
                            break;
                        }
                        Some(c) => {
                            ws.send(Message::Binary(c)).await?;
                        },
                    }
                }
                msg = ws.next() => {
                    match msg {
                        Some(Ok(Message::Binary(input))) => {
                            stdout.write_all(&input).await?;
                            stdout.flush().await?;
                        }
                        Some(Ok(Message::Close(..))) | None => break,
                        _ => continue,
                    }
                }
            }
        }

        Ok(())
    }
}

/// Guard object that will set the terminal to raw mode and restore it
/// to its previous state when it's dropped
struct RawTermiosGuard(libc::c_int, libc::termios);

impl RawTermiosGuard {
    fn stdio_guard() -> Result<RawTermiosGuard, std::io::Error> {
        let fd = std::io::stdout().as_raw_fd();
        let termios = unsafe {
            let mut curr_termios = std::mem::zeroed();
            let r = libc::tcgetattr(fd, &mut curr_termios);
            if r == -1 {
                return Err(std::io::Error::last_os_error());
            }
            curr_termios
        };
        let guard = RawTermiosGuard(fd, termios);
        unsafe {
            let mut raw_termios = termios;
            libc::cfmakeraw(&mut raw_termios);
            let r = libc::tcsetattr(fd, libc::TCSAFLUSH, &raw_termios);
            if r == -1 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(guard)
    }
}

impl Drop for RawTermiosGuard {
    fn drop(&mut self) {
        let r = unsafe { libc::tcsetattr(self.0, libc::TCSADRAIN, &self.1) };
        if r == -1 {
            Err::<(), _>(std::io::Error::last_os_error()).unwrap();
        }
    }
}

async fn stdin_to_websockets_task(
    mut stdinrx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    wstx: tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    // next_raw must live outside loop, because Ctrl-A should work across
    // multiple inbuf reads.
    let mut next_raw = false;

    loop {
        let inbuf = if let Some(inbuf) = stdinrx.recv().await {
            inbuf
        } else {
            continue;
        };

        // Put bytes from inbuf to outbuf, but don't send Ctrl-A unless
        // next_raw is true.
        let mut outbuf = Vec::with_capacity(inbuf.len());

        let mut exit = false;
        for c in inbuf {
            match c {
                // Ctrl-A means send next one raw
                b'\x01' => {
                    if next_raw {
                        // Ctrl-A Ctrl-A should be sent as Ctrl-A
                        outbuf.push(c);
                        next_raw = false;
                    } else {
                        next_raw = true;
                    }
                }
                b'\x03' => {
                    if !next_raw {
                        // Exit on non-raw Ctrl-C
                        exit = true;
                        break;
                    } else {
                        // Otherwise send Ctrl-C
                        outbuf.push(c);
                        next_raw = false;
                    }
                }
                _ => {
                    outbuf.push(c);
                    next_raw = false;
                }
            }
        }

        // Send what we have, even if there's a Ctrl-C at the end.
        if !outbuf.is_empty() {
            wstx.send(outbuf).await.unwrap();
        }

        if exit {
            break;
        }
    }
}
