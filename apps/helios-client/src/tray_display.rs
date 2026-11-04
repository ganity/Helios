pub fn traffic_title(upload: f64, download: f64) -> String {
    fn rate(bytes: f64) -> String {
        let mut value = if bytes.is_finite() {
            bytes.max(0.0)
        } else {
            0.0
        };
        let mut unit = "B";
        for next in ["KiB", "MiB", "GiB"] {
            if value < 1024.0 {
                break;
            }
            value /= 1024.0;
            unit = next;
        }
        format!("{value:.2} {unit}/s")
    }
    format!("↑{:>12}\n↓{:>12}", rate(upload), rate(download))
}

#[cfg(target_os = "macos")]
pub fn update(tray: &tray_icon::TrayIcon, upload: f64, download: f64) {
    use objc2::{AnyThread, MainThreadMarker, runtime::AnyObject};
    use objc2_app_kit::{
        NSColor, NSFont, NSFontAttributeName, NSFontWeightMedium, NSForegroundColorAttributeName,
        NSMutableParagraphStyle, NSParagraphStyleAttributeName,
    };
    use objc2_foundation::{NSAttributedString, NSDictionary, NSString};

    let Some(mtm) = MainThreadMarker::new() else {
        return;
    };
    let Some(item) = tray.ns_status_item() else {
        return;
    };
    // SAFETY: AppKit runs on the UI thread; attribute values match Apple's font/style keys.
    unsafe {
        let Some(button) = item.button(mtm) else {
            return;
        };
        let font = NSFont::monospacedSystemFontOfSize_weight(9.0, NSFontWeightMedium);
        let paragraph = NSMutableParagraphStyle::new();
        paragraph.setMinimumLineHeight(10.0);
        paragraph.setMaximumLineHeight(10.0);
        paragraph.setLineSpacing(0.0);
        let color = NSColor::labelColor();
        let values: [&AnyObject; 3] = [&font, &paragraph, &color];
        let attributes = NSDictionary::from_slices(
            &[
                NSFontAttributeName,
                NSParagraphStyleAttributeName,
                NSForegroundColorAttributeName,
            ],
            &values,
        );
        let title = NSAttributedString::initWithString_attributes(
            NSAttributedString::alloc(),
            &NSString::from_str(&traffic_title(upload, download)),
            Some(&attributes),
        );
        button.setUsesSingleLineMode(false);
        button.setAttributedTitle(&title);
        item.setLength(104.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_use_two_aligned_compact_rows() {
        let title = traffic_title(0.0, 1024.0 * 1024.0 * 12.5);
        let rows: Vec<_> = title.lines().collect();
        assert_eq!(rows.len(), 2);
        assert!(rows[0].starts_with('↑') && rows[0].ends_with("0.00 B/s"));
        assert!(rows[1].starts_with('↓') && rows[1].ends_with("12.50 MiB/s"));
        assert_eq!(rows[0].chars().count(), rows[1].chars().count());
        assert_eq!(traffic_title(f64::NAN, -1.0), traffic_title(0.0, 0.0));
    }
}
