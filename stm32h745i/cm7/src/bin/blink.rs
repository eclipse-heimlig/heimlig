#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

use defmt::*;
use embassy::executor::Spawner;
use embassy::time::{Duration, Timer};
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::Peripherals;
use {defmt_rtt as _, panic_probe as _};


#[embassy::main]
async fn main(spawner: Spawner, p: Peripherals) {
    // info!("Hello World!");

    // let mut led = Output::new(p.PK0, Level::High, Speed::Low); // LCD
    let mut led = Output::new(p.PI13, Level::High, Speed::Low); // Red LED
    // let mut led = Output::new(p.PJ2, Level::High, Speed::Low); // Green LED

    loop {
        info!("low");
        led.set_low();
        Timer::after(Duration::from_millis(50)).await;

        // delay
        // let mut i : u64 = 1<<18;
        // while i > 0 {
        //     i = i - 1;
        // }

        info!("high");
        led.set_high();

        Timer::after(Duration::from_millis(50)).await;

        // delay
        // let mut i : u64 = 1<<18;
        // while i > 0 {
        //     i = i - 1;
        // }
    }
}
