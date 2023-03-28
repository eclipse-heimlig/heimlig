/// Buffer that is overwritten with zeros when dropped.
pub struct ScrubOnDrop<const SIZE: usize> {
    pub data: [u8; SIZE],
}

impl<const SIZE: usize> Drop for ScrubOnDrop<SIZE> {
    fn drop(&mut self) {
        self.data.fill(0);
    }
}

impl<const SIZE: usize> Default for ScrubOnDrop<SIZE> {
    fn default() -> Self {
        ScrubOnDrop::new()
    }
}

impl<const SIZE: usize> ScrubOnDrop<SIZE> {
    pub fn new() -> Self {
        ScrubOnDrop { data: [0u8; SIZE] }
    }
}
