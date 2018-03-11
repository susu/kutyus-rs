
extern crate futures;

#[macro_use]
extern crate tokio_core;

use tokio_core::net::UdpSocket;
use tokio_core::reactor::Core;

struct Receiver {
    socket: UdpSocket,
    buf: Vec<u8>,
    size: usize,
}

impl futures::Future for Receiver {
    type Item = ();
    type Error = std::io::Error;

    fn poll(&mut self) -> Result<futures::Async<Self::Item>, Self::Error>
    {
        loop {
            try_nb!(self.socket.recv_from(&mut self.buf));
            // TODO parse frame and print to stdout or return
        }
    }
}
