/// Test transport: capture the bytes and acknowledge a successful emission.
/// Production code must use prepare/admit/transmit with the real send result.
trait SimulatedTransport {
    fn handle(&mut self, bytes: &[u8], now: u64) -> Result<Vec<u8>, Dropped>;
}

impl SimulatedTransport for Responder {
    fn handle(&mut self, bytes: &[u8], now: u64) -> Result<Vec<u8>, Dropped> {
        let reply = self.prepare(bytes, now)?.admit(now)?;
        let mut captured = Vec::new();
        let result = reply.transmit(|bytes| {
            captured.extend_from_slice(bytes);
            Ok::<_, std::convert::Infallible>(now)
        });
        match result {
            Ok(()) => Ok(captured),
            Err(never) => match never {},
        }
    }
}
