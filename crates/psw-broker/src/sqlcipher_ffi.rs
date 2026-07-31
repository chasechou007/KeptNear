use std::ffi::c_void;

use rusqlite::{ffi, Connection};

const MAIN_DATABASE_NAME: &[u8] = b"main\0";
const RAW_KEY_LITERAL_LENGTH: usize = 67;

pub(crate) fn set_raw_key(
    connection: &Connection,
    encoded_key: &[u8; RAW_KEY_LITERAL_LENGTH],
) -> Result<(), i32> {
    // SAFETY: `connection` remains exclusively borrowed for this call; its
    // handle is valid for the Connection lifetime. Both pointers reference
    // stable buffers that outlive the synchronous sqlite3_key_v2 call.
    let result = unsafe {
        ffi::sqlite3_key_v2(
            connection.handle(),
            MAIN_DATABASE_NAME.as_ptr().cast(),
            encoded_key.as_ptr().cast::<c_void>(),
            encoded_key.len() as i32,
        )
    };
    if result == ffi::SQLITE_OK {
        Ok(())
    } else {
        Err(result)
    }
}
