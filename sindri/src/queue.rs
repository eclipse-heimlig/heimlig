use heapless::spsc::Queue;

#[derive(Debug)]
pub enum Error {
    BufferSize,
}

/// Create SPSC queue in preallocated memory buffer.
///
/// # Arguments
///
/// * `buffer`: Preallocated buffer of at least `core::mem::size_of::Queue<T, { N }>()` size.
///
/// # Safety
///
/// This function will use raw memory access to create a new queue in the provided memory buffer.
/// The caller must make sure that the memory buffer is not reused or freed before the the returned
/// queue is dropped.
///
/// # Examples
///
/// ```
/// use heapless::spsc::Queue;
/// type Element = u32;
///
/// const QUEUE_ELEMENTS: usize = 10;
/// const QUEUE_BYTES: usize = core::mem::size_of::<Queue<Element, QUEUE_ELEMENTS>>();
/// static mut QUEUE_BUFFER: [u8; QUEUE_BYTES] = [0u8; QUEUE_BYTES];
/// let queue = unsafe { sindri::queue::create_queue_in_buffer::<Element, QUEUE_ELEMENTS>(&mut QUEUE_BUFFER) };
/// ```
pub unsafe fn create_queue_in_buffer<T, const N: usize>(
    buffer: &mut [u8],
) -> Result<&mut Queue<T, N>, Error> {
    if buffer.len() < core::mem::size_of::<Queue<T, N>>() {
        return Err(Error::BufferSize);
    }
    core::ptr::write(
        buffer.as_mut_ptr() as *mut Queue<T, N>,
        Queue::<T, N>::new(),
    );
    Ok(&mut *(buffer.as_mut_ptr() as *mut Queue<T, N>))
}

#[cfg(test)]
mod test {
    use super::*;

    type Element = u32;

    #[test]
    fn create_queue() -> Result<(), Error> {
        // Simulate externally defined memory region
        const QUEUE_ELEMENTS: usize = 10;
        const QUEUE_BYTES: usize = core::mem::size_of::<Queue<Element, QUEUE_ELEMENTS>>();
        static mut QUEUE_BUFFER: [u8; QUEUE_BYTES] = [0u8; QUEUE_BYTES];

        // Create queue
        let queue =
            unsafe { create_queue_in_buffer::<Element, QUEUE_ELEMENTS>(&mut QUEUE_BUFFER) }?;
        let (mut producer, mut consumer) = queue.split();

        // Use queue
        assert_eq!(producer.len(), 0);
        assert_eq!(consumer.len(), 0);
        let element_in = 0x12345678;
        assert!(producer.enqueue(element_in.clone()).is_ok());
        assert_eq!(producer.len(), 1);
        assert_eq!(consumer.len(), 1);
        let element_out = consumer.dequeue().unwrap();
        assert_eq!(producer.len(), 0);
        assert_eq!(consumer.len(), 0);
        assert_eq!(element_in, element_out);
        Ok(())
    }

    #[test]
    fn create_queue_buffer_too_small() {
        const QUEUE_ELEMENTS: usize = 10;
        const QUEUE_BYTES: usize = core::mem::size_of::<Queue<Element, QUEUE_ELEMENTS>>() - 1; // Buffer is too short
        static mut QUEUE_BUFFER: [u8; QUEUE_BYTES] = [0u8; QUEUE_BYTES];
        match unsafe { create_queue_in_buffer::<Element, QUEUE_ELEMENTS>(&mut QUEUE_BUFFER) } {
            Err(Error::BufferSize) => {}
            _ => {
                panic!("Expected error during queue creation.")
            }
        }
    }
}
