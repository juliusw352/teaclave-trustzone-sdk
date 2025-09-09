#![allow(dead_code)]

use rand::distr::{Distribution, StandardUniform};
use rand::Rng;

#[derive(Debug)]
pub enum CanFrameOptions {
    StandardFrame,
    Error,
    Remote,
    Overload,
}
#[derive(Debug)]
pub struct CanFrame {
    frame_type: CanFrameOptions,
    value: String,
}

impl Distribution<CanFrameOptions> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> CanFrameOptions {
        match rng.random_range(0..=3) {
            0 => CanFrameOptions::StandardFrame,
            1 => CanFrameOptions::Error,
            2 => CanFrameOptions::Remote,
            _ => CanFrameOptions::Overload,
        }
    }
}

pub fn generate_standard_frame() -> String {
    let mut rng = rand::rng();

    let mut frame_data = String::from('0');
    frame_data.push_str(&generate_random_bits(11)); // 11 bits for standard ID
    frame_data.push('0'); // RTR bit
    frame_data.push('0'); // IDE bit
    frame_data.push('0'); // r0 bit
    let data_length: u8 = rng.random_range(0..8);
    frame_data.push_str(&format!("{:04b}", data_length)); // DLC (4 bits)
    frame_data.push_str(&generate_random_bits(data_length as usize * 8)); // Data field
    frame_data.push_str(&generate_random_bits(15)); // CRC (15 bits): for the sake of this demo it is randomly generated.
    frame_data.push('1'); // CRC delimiter
    frame_data.push_str(&generate_random_bits(1)); // ACK slot
    frame_data.push('1'); // ACK delimiter
    frame_data.push('0'); // EOF (7 bits)
    frame_data.push('1'); // IFS (3 bits)
    frame_data
}

// This error frame is very simplified, in reality such a frame would be interrupting a
// different frame. Here it is its own standalone frame for simplicity.
pub fn generate_error_frame() -> String {
    let mut rng = rand::rng();
    let mut frame_data = String::from("11111111"); // Error delimiter

    let err_type: bool = rng.random_bool(0.5);
    frame_data.insert_str(0, if err_type { "111111" } else { "000000" });
    frame_data
}

pub fn generate_remote_frame() -> String {
    let mut rng = rand::rng();

    let mut frame_data = String::from("0");
    frame_data.push_str(&generate_random_bits(11)); // 11 bits for standard ID
    frame_data.push('1'); // RTR bit
    frame_data.push('0'); // IDE bit
    frame_data.push('0'); // r0 bit
    let data_length: u8 = rng.random_range(0..8);
    frame_data.push_str(&format!("{:04b}", data_length)); // DLC (4 bits)
    frame_data.push_str(&generate_random_bits(15)); // CRC (15 bits)
    frame_data.push('1'); // CRC delimiter
    frame_data.push_str(&generate_random_bits(1)); // ACK slot
    frame_data.push('1'); // ACK delimiter
    frame_data.push('0'); // EOF (7 bits)
    frame_data.push('1'); // IFS (3 bits)
    frame_data
}

pub fn generate_overload_frame() -> String {
    String::from("00000011111111") // Overload frame pattern
}

fn generate_random_bits(len: usize) -> String {
    let mut rng = rand::rng();
    (0..len)
        .map(|_| if rng.random_bool(0.5) { '1' } else { '0' })
        .collect()
}

pub fn get_frame() {
    let random_frame: CanFrameOptions = rand::random();

    let frame = match random_frame {
        CanFrameOptions::StandardFrame => CanFrame {
            frame_type: CanFrameOptions::StandardFrame,
            value: generate_standard_frame(),
        },
        CanFrameOptions::Error => CanFrame {
            frame_type: CanFrameOptions::Error,
            value: generate_error_frame(),
        },
        CanFrameOptions::Remote => CanFrame {
            frame_type: CanFrameOptions::Remote,
            value: generate_remote_frame(),
        },
        CanFrameOptions::Overload => CanFrame {
            frame_type: CanFrameOptions::Overload,
            value: generate_overload_frame(),
        },
    };
    println!("Generated CAN Frame: {:?}", frame);
}
