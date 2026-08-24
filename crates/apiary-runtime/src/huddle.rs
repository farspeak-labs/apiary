//! Buzz huddle audio — the wire format and the turn detector.
//!
//! Buzz carries huddle voice over a plain WebSocket in `buzz-relay`
//! (`wss://…/huddle/{channel_id}/audio`), authenticated per participant with
//! a NIP-42 challenge. There is no SFU: the relay **forwards opaque Opus
//! frames between peers rather than mixing them**, which hands us three
//! things for free.
//!
//! 1. Per-peer streams, so speaker attribution needs no diarization.
//! 2. No mix, so an agent never hears itself — the echo cancellation that
//!    dominates open-mic work simply does not arise here.
//! 3. A loudness metric in the header, so voice activity is visible without
//!    decoding a single Opus packet.
//!
//! This module is the part that can be tested without a relay, a codec, or a
//! microphone: parsing frames and deciding when someone started and stopped
//! talking.

/// Frame protocol v2: an 8-byte big-endian header, then the Opus payload.
pub const HEADER_LEN: usize = 8;
/// Huddle audio is 48 kHz; timestamps count samples at that rate.
pub const SAMPLE_RATE: u32 = 48_000;
/// 0 dBov is full scale and real levels are negative. The relay clamps
/// rather than drops — losing a metric beats losing audio — and so do we.
pub const MIN_DBOV: i8 = -127;
pub const MAX_DBOV: i8 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub sequence: u16,
    /// Sample clock at 48 kHz. Wraps roughly every 24.8 hours.
    pub timestamp: u32,
    /// Loudness, dB relative to overload: 0 is full scale, -127 is silence.
    pub level_dbov: i8,
    pub flags: u8,
    /// Opaque to us: the relay never inspects it and neither do we until a
    /// decoder is attached.
    pub opus: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// Fewer than 8 bytes: there is no header to read.
    TooShort(usize),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::TooShort(n) => {
                write!(f, "huddle frame is {n} bytes; the header alone needs {HEADER_LEN}")
            }
        }
    }
}

impl Frame {
    pub fn parse(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < HEADER_LEN {
            return Err(FrameError::TooShort(bytes.len()));
        }
        Ok(Self {
            sequence: u16::from_be_bytes([bytes[0], bytes[1]]),
            timestamp: u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
            level_dbov: (bytes[6] as i8).clamp(MIN_DBOV, MAX_DBOV),
            flags: bytes[7],
            opus: bytes[HEADER_LEN..].to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.opus.len());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.push(self.level_dbov.clamp(MIN_DBOV, MAX_DBOV) as u8);
        out.push(self.flags);
        out.extend_from_slice(&self.opus);
        out
    }

    /// Elapsed seconds from `earlier` to this frame, tolerating the 24.8-hour
    /// wrap of the sample clock.
    pub fn seconds_since(&self, earlier: u32) -> f64 {
        f64::from(self.timestamp.wrapping_sub(earlier)) / f64::from(SAMPLE_RATE)
    }
}

/// What the gate concluded about one peer on this frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Turn {
    /// Still whatever it was: silence continuing, or speech continuing.
    Unchanged,
    /// This peer just started talking.
    Started,
    /// This peer has been quiet long enough to call the turn over.
    Ended,
}

/// Per-peer turn detection driven entirely by the header's loudness metric.
///
/// Hysteresis matters more than the threshold: a single quiet frame in the
/// middle of a sentence is a breath, not the end of a turn. Speech starts on
/// the first loud frame and ends only after a sustained gap, so the detector
/// does not chop a speaker mid-thought.
#[derive(Debug, Clone)]
pub struct SpeechGate {
    /// At or above this level, a frame counts as speech.
    pub floor_dbov: i8,
    /// Silence must persist this long before a turn is called ended.
    pub hang_over_secs: f64,
    speaking: bool,
    last_loud: Option<u32>,
}

impl SpeechGate {
    pub fn new(floor_dbov: i8, hang_over_secs: f64) -> Self {
        Self {
            floor_dbov,
            hang_over_secs,
            speaking: false,
            last_loud: None,
        }
    }

    pub fn is_speaking(&self) -> bool {
        self.speaking
    }

    pub fn observe(&mut self, frame: &Frame) -> Turn {
        let loud = frame.level_dbov >= self.floor_dbov;
        if loud {
            self.last_loud = Some(frame.timestamp);
            if !self.speaking {
                self.speaking = true;
                return Turn::Started;
            }
            return Turn::Unchanged;
        }
        if self.speaking {
            let quiet_for = self
                .last_loud
                .map(|t| frame.seconds_since(t))
                .unwrap_or_default();
            if quiet_for >= self.hang_over_secs {
                self.speaking = false;
                return Turn::Ended;
            }
        }
        Turn::Unchanged
    }
}

impl Default for SpeechGate {
    /// -45 dBov and 700 ms: quiet enough to ignore room tone, patient enough
    /// to sit through a breath between clauses.
    fn default() -> Self {
        Self::new(-45, 0.7)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(seq: u16, ts: u32, level: i8) -> Frame {
        Frame {
            sequence: seq,
            timestamp: ts,
            level_dbov: level,
            flags: 0,
            opus: vec![0xfc, 0x01, 0x02],
        }
    }

    #[test]
    fn frames_round_trip_through_the_wire_format() {
        let original = frame(7, 480_000, -30);
        let parsed = Frame::parse(&original.encode()).expect("valid frame");
        assert_eq!(parsed, original);
        // The header is big-endian, per the protocol.
        let bytes = original.encode();
        assert_eq!(&bytes[0..2], &7u16.to_be_bytes());
        assert_eq!(&bytes[2..6], &480_000u32.to_be_bytes());
        assert_eq!(bytes[6] as i8, -30);
    }

    #[test]
    fn a_frame_without_a_header_is_refused_by_length_not_guessed_at() {
        assert_eq!(Frame::parse(&[0u8; 7]), Err(FrameError::TooShort(7)));
        // Exactly a header and no audio is legal — a silence frame.
        let empty = Frame::parse(&[0u8; HEADER_LEN]).expect("header-only frame");
        assert!(empty.opus.is_empty());
    }

    #[test]
    fn an_impossible_level_is_clamped_rather_than_dropped() {
        // Positive dBov cannot exist; the relay clamps and so do we, because
        // losing a metric beats losing audio.
        let mut bytes = frame(1, 0, 0).encode();
        bytes[6] = 42u8; // a nonsense positive level
        assert_eq!(Frame::parse(&bytes).unwrap().level_dbov, MAX_DBOV);
        bytes[6] = (-128i8) as u8;
        assert_eq!(Frame::parse(&bytes).unwrap().level_dbov, MIN_DBOV);
        // and the audio survived the clamp
        assert_eq!(Frame::parse(&bytes).unwrap().opus, vec![0xfc, 0x01, 0x02]);
    }

    #[test]
    fn the_sample_clock_may_wrap_without_inventing_a_day_of_silence() {
        let late = frame(2, 100, -20); // wrapped past u32::MAX
        let earlier = u32::MAX - 100 + 1;
        assert!((late.seconds_since(earlier) - (200.0 / 48_000.0)).abs() < 1e-9);
    }

    #[test]
    fn a_breath_mid_sentence_does_not_end_the_turn() {
        let mut gate = SpeechGate::new(-45, 0.7);
        assert_eq!(gate.observe(&frame(0, 0, -20)), Turn::Started);
        // 300 ms of quiet: a pause for breath, not the end of a turn.
        let pause = (0.3 * f64::from(SAMPLE_RATE)) as u32;
        assert_eq!(gate.observe(&frame(1, pause, -80)), Turn::Unchanged);
        assert!(gate.is_speaking());
        // Talking resumes, and the hang-over clock restarts from here.
        let resume = (0.4 * f64::from(SAMPLE_RATE)) as u32;
        assert_eq!(gate.observe(&frame(2, resume, -18)), Turn::Unchanged);
        let short_gap = resume + (0.6 * f64::from(SAMPLE_RATE)) as u32;
        assert_eq!(gate.observe(&frame(3, short_gap, -90)), Turn::Unchanged);
    }

    #[test]
    fn a_sustained_gap_ends_the_turn_exactly_once() {
        let mut gate = SpeechGate::new(-45, 0.7);
        gate.observe(&frame(0, 0, -20));
        let gap = (0.8 * f64::from(SAMPLE_RATE)) as u32;
        assert_eq!(gate.observe(&frame(1, gap, -90)), Turn::Ended);
        assert!(!gate.is_speaking());
        // Continued silence is not a stream of Ended events.
        let more = gap + (5.0 * f64::from(SAMPLE_RATE)) as u32;
        assert_eq!(gate.observe(&frame(2, more, -90)), Turn::Unchanged);
        // And the next utterance starts cleanly.
        assert_eq!(gate.observe(&frame(3, more + 480, -10)), Turn::Started);
    }

    #[test]
    fn a_room_that_is_merely_quiet_never_starts_a_turn() {
        let mut gate = SpeechGate::default();
        for i in 0..50 {
            let f = frame(i, u32::from(i) * 960, -60); // room tone
            assert_eq!(gate.observe(&f), Turn::Unchanged);
        }
        assert!(!gate.is_speaking());
    }
}
