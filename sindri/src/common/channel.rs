use alloc::vec::Vec;

pub trait Sender {
    fn id(&self) -> u32;
    fn send(&mut self, data: &[u8]);
}

pub trait Receiver {
    fn id(&self) -> u32;
    fn recv(&mut self) -> Vec<u8>;
}
