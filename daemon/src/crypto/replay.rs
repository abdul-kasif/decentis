/// A 128-bit sliding window to prevent cryptographic replay attacks.
/// Tracks the highest sequence number seen and maintains a bitmap of the last 128 packets.
#[derive(Debug)]
pub struct ReplayFilter {
    highest_seq: u64,
    bitmap: u128,
    started: bool,
}

impl ReplayFilter {
    pub fn new() -> Self {
        Self {
            highest_seq: 0,
            bitmap: 0,
            started: false,
        }
    }

    /// Checks if a sequence number is valid and marks it as seen.
    /// Returns `true` if the packet should be accepted, `false` if it is a replay or too old.
    pub fn check_and_mark(&mut self, seq: u64) -> bool {
        if !self.started {
            self.highest_seq = seq;
            self.bitmap = 1;
            self.started = true;
            return true;
        }

        if seq > self.highest_seq {
            // New highest sequence number: shift the window
            let diff = seq - self.highest_seq;
            if diff >= 128 {
                // We jumped too far ahead; wipe the bitmap
                self.bitmap = 1;
            } else {
                // Shift the bitmap left and set the 0th bit for the new sequence
                self.bitmap = (self.bitmap << diff) | 1;
            }
            self.highest_seq = seq;
            true
        } else {
            // Packet arrived out of order (seq <= highest_seq)
            let delta = self.highest_seq - seq;

            if delta >= 128 {
                // Packet is older than our 128-bit window (too old)
                return false;
            }

            // Check if the bit at index `delta` is already set
            let bit_mask = 1 << delta;
            if (self.bitmap & bit_mask) != 0 {
                // We already saw this packet (replay attack)
                return false;
            }

            // Mark the packet as seen
            self.bitmap |= bit_mask;
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_order() {
        let mut filter = ReplayFilter::new();
        assert!(filter.check_and_mark(1));
        assert!(filter.check_and_mark(2));
        assert!(filter.check_and_mark(3));
    }

    #[test]
    fn test_duplicate_rejection() {
        let mut filter = ReplayFilter::new();
        assert!(filter.check_and_mark(10));
        assert!(!filter.check_and_mark(10), "Duplicate should be rejected");
    }

    #[test]
    fn test_out_of_order_acceptance() {
        let mut filter = ReplayFilter::new();
        assert!(filter.check_and_mark(10)); // window shifts to 10
        assert!(filter.check_and_mark(8)); // out of order, but within window
        assert!(!filter.check_and_mark(8)); // duplicate out of order
    }

    #[test]
    fn test_too_old_rejection() {
        let mut filter = ReplayFilter::new();
        assert!(filter.check_and_mark(200));
        assert!(
            !filter.check_and_mark(50),
            "Delta >= 128 should be rejected"
        );
    }
}
