#![no_std]

extern crate alloc;

pub mod crypto;
pub mod queue;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
