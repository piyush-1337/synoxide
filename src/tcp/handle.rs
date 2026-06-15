pub struct TcpHandle<'a> {
    payload: &'a [u8],
}

impl<'a> TcpHandle<'a> {
    pub fn read_data(&mut self) -> &[u8] {
        self.payload
    }
}
