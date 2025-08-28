#![cfg(windows)]
use std::mem::zeroed;
use windows::Win32::Graphics::Gdi::{BITMAP, GetObjectW};

mod utils;
use win_cred_provider::credentials::types::UdsFieldId;

#[test]
fn test_get_bitmap_correct_field() -> windows::core::Result<()> {
    let factory = utils::com::ClassFactoryTest::new()?;
    let credential = factory.create_credential()?;

    let bitmap = unsafe { credential.GetBitmapValue(UdsFieldId::TileImage as u32) }?;

    let mut bmp: BITMAP = unsafe { zeroed() };

    unsafe {
        GetObjectW(
            bitmap.into(), // converts HBITMAP → HGDIOBJ
            std::mem::size_of::<BITMAP>() as i32,
            Some(&mut bmp as *mut _ as *mut core::ffi::c_void), // pointer as Option<*mut core::ffi::c_void>
        );
    }

    assert!(bmp.bmWidth == 128);
    assert!(bmp.bmHeight == 128);
    assert!(bmp.bmPlanes == 1);

    Ok(())
}

#[test]
fn test_get_bitmap_incorrect_field() -> windows::core::Result<()> {
    let factory = utils::com::ClassFactoryTest::new()?;
    let credential = factory.create_credential()?;

    let result = unsafe { credential.GetBitmapValue(9999) }; // Invalid field ID

    assert!(result.is_err());
    Ok(())
}
