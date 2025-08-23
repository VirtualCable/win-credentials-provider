use windows::Win32::Graphics::Gdi::*;

static BITMAP: &[u8] = include_bytes!("../img/uds.bmp");

pub fn get_uds_bitmap(width: i32, height: i32) -> HBITMAP {
    let bmi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width,
            biHeight: -height, // negativo para que no se invierta verticalmente
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        bmiColors: [RGBQUAD::default()],
    };

    let dc = unsafe { CreateCompatibleDC(None) };

    unsafe {
        CreateDIBitmap(
            GetDC(None),
            Some(&bmi.bmiHeader),
            CBM_INIT as u32,
            Some(BITMAP.as_ptr() as *const _),
            Some(&bmi),
            DIB_RGB_COLORS,
        )
    }
}