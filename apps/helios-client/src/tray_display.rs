pub fn traffic_title(upload: f64, download: f64) -> String {
    fn rate(bytes: f64) -> String {
        let mut value = if bytes.is_finite() {
            bytes.max(0.0)
        } else {
            0.0
        };
        let units = ["B", "K", "M", "G"];
        let mut unit = 0;
        while unit < units.len() - 1 && value >= 999.5 {
            value /= 1000.0;
            unit += 1;
        }
        value = value.min(999.0);
        let number = if value < 9.995 {
            format!("{value:>4.2}")
        } else if value < 99.95 {
            format!("{value:>4.1}")
        } else {
            format!("{value:>4.0}")
        };
        format!("{number} {}", units[unit])
    }
    format!("↑ {}\n↓ {}", rate(upload), rate(download))
}

#[cfg(any(test, target_os = "macos"))]
const STATUS_IMAGE_WIDTH: f64 = 64.0;
#[cfg(any(test, target_os = "macos"))]
const STATUS_ITEM_WIDTH: f64 = 68.0;

#[cfg(target_os = "macos")]
pub fn update(tray: &tray_icon::TrayIcon, connected: bool, upload: f64, download: f64) {
    use block2::RcBlock;
    use objc2::{
        AnyThread, MainThreadMarker,
        rc::Retained,
        runtime::{AnyObject, Bool},
    };
    use objc2_app_kit::{
        NSAccessibility, NSAttributedStringNSStringDrawing, NSBezierPath, NSCellImagePosition,
        NSColor, NSCompositingOperation, NSFont, NSFontAttributeName, NSFontWeightMedium,
        NSForegroundColorAttributeName, NSImage, NSImageScaling,
    };
    use objc2_foundation::{
        NSAttributedString, NSData, NSDictionary, NSPoint, NSRect, NSSize, NSString,
    };

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
        let data = NSData::with_bytes(super::TRAY_ICON);
        let Some(icon) = NSImage::initWithData(NSImage::alloc(), &data) else {
            return;
        };
        let font = NSFont::monospacedSystemFontOfSize_weight(8.5, NSFontWeightMedium);
        let color = NSColor::blackColor();
        let values: [&AnyObject; 2] = [&font, &color];
        let attributes = NSDictionary::from_slices(
            &[NSFontAttributeName, NSForegroundColorAttributeName],
            &values,
        );
        let title = traffic_title(upload, download);
        button.setAccessibilityLabel(Some(&NSString::from_str(&format!(
            "Helios · {} · {title}",
            crate::i18n::t(if connected { "已连接" } else { "未连接" }),
        ))));
        let rows: Vec<Retained<NSAttributedString>> = title
            .lines()
            .map(|row| {
                NSAttributedString::initWithString_attributes(
                    NSAttributedString::alloc(),
                    &NSString::from_str(row),
                    Some(&attributes),
                )
            })
            .collect();
        // One resolution-independent image keeps the icon and both rows inside the menu bar.
        let draw = RcBlock::new(move |_rect: NSRect| -> Bool {
            icon.drawInRect_fromRect_operation_fraction(
                NSRect::new(NSPoint::new(1.0, 3.0), NSSize::new(16.0, 16.0)),
                NSRect::ZERO,
                NSCompositingOperation::SourceOver,
                if connected { 1.0 } else { 0.35 },
            );
            if !connected {
                NSColor::blackColor().setStroke();
                let slash = NSBezierPath::bezierPath();
                slash.setLineWidth(1.8);
                slash.moveToPoint(NSPoint::new(2.0, 3.0));
                slash.lineToPoint(NSPoint::new(17.0, 18.0));
                slash.stroke();
            }
            rows[0].drawAtPoint(NSPoint::new(20.0, 11.0));
            rows[1].drawAtPoint(NSPoint::new(20.0, 1.0));
            Bool::YES
        });
        let image = NSImage::imageWithSize_flipped_drawingHandler(
            NSSize::new(STATUS_IMAGE_WIDTH, 22.0),
            false,
            &draw,
        );
        image.setTemplate(true);
        button.setTitle(&NSString::from_str(""));
        button.setImagePosition(NSCellImagePosition::ImageOnly);
        button.setImageScaling(NSImageScaling::ScaleNone);
        button.setImage(Some(&image));
        item.setLength(STATUS_ITEM_WIDTH);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_use_two_compact_rows_that_fit_the_status_image() {
        let title = traffic_title(0.0, 12_500_000.0);
        let rows: Vec<_> = title.lines().collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows, ["↑ 0.00 B", "↓ 12.5 M"]);
        assert_eq!(
            traffic_title(128_400.0, 0.0).lines().next(),
            Some("↑  128 K")
        );
        assert_eq!(traffic_title(f64::NAN, -1.0), traffic_title(0.0, 0.0));
        for rate in [0.0, 1023.0, 1024.0, 1024.0 * 1023.9, f64::MAX] {
            assert!(
                traffic_title(rate, rate)
                    .lines()
                    .all(|row| row.chars().count() == 8)
            );
        }
        assert_eq!(STATUS_IMAGE_WIDTH, 64.0);
        assert_eq!(STATUS_ITEM_WIDTH, 68.0);
    }
}
