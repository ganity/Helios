use helios_protocol::FRAME_HEADER_LEN;

/// Padding applies to plaintext control-frame lengths, not TLS/QUIC wire lengths.
pub(crate) fn random_padding(payload_len: usize) -> Result<Vec<u8>, getrandom::Error> {
    let tiers = [256usize, 512, 1024, 2048];
    let minimum = payload_len.saturating_add(FRAME_HEADER_LEN);
    let first = tiers.iter().position(|tier| *tier >= minimum);
    let Some(first) = first else {
        return Ok(Vec::new());
    };
    let mut choice = [0u8; 1];
    getrandom::fill(&mut choice)?;
    let tier = tiers[first + usize::from(choice[0]) % (tiers.len() - first)];
    let mut padding = vec![0; tier - minimum];
    getrandom::fill(&mut padding)?;
    Ok(padding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_control_padding_stays_in_tiers_and_never_underflows() {
        for payload in [38, 80, 250, 500, 1000, 2000, 2048, usize::MAX] {
            for _ in 0..8 {
                let padding = random_padding(payload).unwrap();
                if payload.saturating_add(FRAME_HEADER_LEN) > 2048 {
                    assert!(padding.is_empty());
                } else {
                    assert!(
                        [256, 512, 1024, 2048]
                            .contains(&(payload + FRAME_HEADER_LEN + padding.len()))
                    );
                }
            }
        }
    }
}
