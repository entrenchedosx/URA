//! Refit only on startup, monitor/DPI/work-area changes and observed restore transitions. Ordinary
//! resizing/dragging keeps the user's placement and never schedules a repaint.
#[derive(Default)]
pub struct WindowPlacementGuard {
    #[cfg(windows)]
    previous: Option<windows::State>,
}

impl WindowPlacementGuard {
    pub fn update(&mut self, frame: &eframe::Frame) {
        #[cfg(windows)]
        windows::update(self, frame);
        #[cfg(not(windows))]
        let _ = frame;
    }
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
struct Rect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

#[cfg(any(windows, test))]
fn fit(window: Rect, work: Rect) -> Option<Rect> {
    let width = i64::from(window.right) - i64::from(window.left);
    let height = i64::from(window.bottom) - i64::from(window.top);
    let available_width = i64::from(work.right) - i64::from(work.left);
    let available_height = i64::from(work.bottom) - i64::from(work.top);
    if width <= 0 || height <= 0 || available_width <= 0 || available_height <= 0 {
        return None;
    }
    let width = width.min(available_width).min(i64::from(i32::MAX));
    let height = height.min(available_height).min(i64::from(i32::MAX));
    let left = i64::from(window.left).clamp(i64::from(work.left), i64::from(work.right) - width);
    let top = i64::from(window.top).clamp(i64::from(work.top), i64::from(work.bottom) - height);
    let fitted = Rect {
        left: left as i32,
        top: top as i32,
        right: (left + width) as i32,
        bottom: (top + height) as i32,
    };
    (fitted != window).then_some(fitted)
}

#[cfg(windows)]
mod windows {
    use super::{Rect, WindowPlacementGuard, fit};
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use std::{ffi::c_void, mem::size_of, ptr::null_mut};

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) struct State {
        monitor: isize,
        dpi: u32,
        work: Rect,
        maximized: bool,
        minimized: bool,
    }

    #[repr(C)]
    struct MonitorInfo {
        size: u32,
        monitor: Rect,
        work: Rect,
        flags: u32,
    }

    #[link(name = "user32")]
    unsafe extern "system" {
        fn GetDpiForWindow(window: *mut c_void) -> u32;
        fn MonitorFromWindow(window: *mut c_void, flags: u32) -> *mut c_void;
        fn GetMonitorInfoW(monitor: *mut c_void, info: *mut MonitorInfo) -> i32;
        fn GetWindowRect(window: *mut c_void, rect: *mut Rect) -> i32;
        fn IsZoomed(window: *mut c_void) -> i32;
        fn IsIconic(window: *mut c_void) -> i32;
        fn SetWindowPos(
            window: *mut c_void,
            after: *mut c_void,
            x: i32,
            y: i32,
            width: i32,
            height: i32,
            flags: u32,
        ) -> i32;
    }

    pub(super) fn update(guard: &mut WindowPlacementGuard, frame: &eframe::Frame) {
        let Ok(handle) = frame.window_handle() else {
            return;
        };
        let RawWindowHandle::Win32(handle) = handle.as_raw() else {
            return;
        };
        let window = handle.hwnd.get() as *mut c_void;
        // SAFETY: the live frame owns this HWND throughout the UI callback. All
        // queried/updated rectangles use physical pixels on the same thread in
        // winit's per-monitor-DPI-aware context. No other window is touched.
        unsafe {
            let monitor = MonitorFromWindow(window, 2); // nearest monitor
            let dpi = GetDpiForWindow(window);
            if monitor.is_null() || dpi == 0 {
                return;
            }
            let mut info = MonitorInfo {
                size: size_of::<MonitorInfo>() as u32,
                monitor: Rect::default(),
                work: Rect::default(),
                flags: 0,
            };
            if GetMonitorInfoW(monitor, &mut info) == 0 {
                return;
            }
            let state = State {
                monitor: monitor as isize,
                dpi,
                work: info.work,
                maximized: IsZoomed(window) != 0,
                minimized: IsIconic(window) != 0,
            };
            if guard.previous == Some(state) {
                return;
            }
            if state.maximized || state.minimized {
                guard.previous = Some(state);
                return;
            }
            let mut rect = Rect::default();
            if GetWindowRect(window, &mut rect) == 0 {
                return;
            }
            if let Some(rect) = fit(rect, info.work) {
                // Preserve activation/z-order; Windows sends the ordinary
                // resize/move events back through winit. Do not request repaint.
                if SetWindowPos(
                    window,
                    null_mut(),
                    rect.left,
                    rect.top,
                    rect.right - rect.left,
                    rect.bottom - rect.top,
                    0x0010 | 0x0004,
                ) == 0
                {
                    return;
                }
            }
            guard.previous = Some(state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Rect, fit};
    fn rect(left: i32, top: i32, width: i32, height: i32) -> Rect {
        Rect {
            left,
            top,
            right: left + width,
            bottom: top + height,
        }
    }
    #[test]
    fn dpi_restore_oversize_fits_the_work_area_including_taskbar() {
        let work = rect(0, 0, 1920, 1008);
        assert_eq!(fit(rect(199, 571, 2220, 1380), work), Some(work));
        assert_eq!(
            fit(rect(199, 571, 1480, 952), work),
            Some(rect(199, 56, 1480, 952))
        );
    }
    #[test]
    fn negative_monitor_origin_and_valid_user_placement_are_preserved() {
        let work = rect(-1920, -200, 1920, 1000);
        assert_eq!(fit(rect(-1800, -100, 1200, 700), work), None);
        assert_eq!(
            fit(rect(-1000, 500, 1200, 700), work),
            Some(rect(-1200, 100, 1200, 700))
        );
    }
    #[test]
    fn malformed_rectangles_do_not_produce_window_commands() {
        assert_eq!(fit(rect(0, 0, 0, 600), rect(0, 0, 1920, 1008)), None);
        assert_eq!(fit(rect(0, 0, 900, 600), rect(0, 0, 1920, 0)), None);
    }
}
