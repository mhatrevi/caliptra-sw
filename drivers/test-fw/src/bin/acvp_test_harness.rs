// Licensed under the Apache-2.0 license

#![no_main]
#![no_std]

#[allow(unused)]
use caliptra_test_harness::{self, println};

use caliptra_drivers::Mailbox;
use caliptra_drivers_test_bin::{
    AcvpCapabilitiesResp, ACVP_CMD_GET_CAPABILITIES, ACVP_MAX_DATA_SIZE,
    ACVP_PROTOCOL_VERSION,
};
use caliptra_registers::mbox::MboxCsr;
use zerocopy::IntoBytes;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
extern "C" fn main() {
    let mut mailbox = unsafe { Mailbox::new(MboxCsr::new()) };

    loop {
        let Some(mut transaction) = mailbox.try_start_recv_txn() else {
            continue;
        };

        match transaction.cmd() {
            ACVP_CMD_GET_CAPABILITIES if transaction.dlen() == 0 => {
                let response = AcvpCapabilitiesResp {
                    protocol_version: ACVP_PROTOCOL_VERSION,
                    supported_algorithms: 0,
                    max_data_size: ACVP_MAX_DATA_SIZE,
                };
                transaction.send_response(response.as_bytes()).unwrap();
            }
            _ => transaction.complete(false).unwrap(),
        }
    }
}