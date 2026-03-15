/// Congestion / rate control algorithm.
///
/// Uses a proportional controller to converge sending rate to a point where
/// the observed packet loss rate equals the target: `1 - 1/multiplier`.
///
/// Algorithm per measurement interval:
///   error = target_loss - smoothed_loss
///   rate *= base^error
///
/// This provides exponential ramp-up when far from target and smooth
/// convergence near equilibrium.

#[derive(Debug)]
pub struct RateController {
    /// Current sending rate in packets per second
    rate: f64,
    /// Smoothed loss rate (exponential moving average)
    smoothed_loss: f64,
    /// Target loss rate = 1 - 1/multiplier
    target_loss: f64,
    /// Base for exponential adjustment
    base: f64,
    /// Smoothing factor for EMA (alpha)
    alpha: f64,
    /// Minimum rate (packets/sec)
    min_rate: f64,
    /// Maximum rate (packets/sec) - safety cap
    max_rate: f64,
}

impl RateController {
    pub fn new(multiplier: f64, base: f64) -> Self {
        let target_loss = 1.0 - 1.0 / multiplier;
        RateController {
            rate: 10.0, // start at 10 pps
            smoothed_loss: 0.0,
            target_loss,
            base,
            alpha: 0.2,
            min_rate: 1.0,
            max_rate: 10_000_000.0, // 10M pps safety cap
        }
    }

    /// Update the rate controller with observed loss and return the new rate.
    ///
    /// `sent`: packets sent this interval
    /// `acked`: packets acknowledged this interval
    pub fn update(&mut self, sent: u64, acked: u64) -> f64 {
        if sent == 0 {
            return self.rate;
        }

        let loss = 1.0 - (acked as f64 / sent as f64);
        let loss = loss.clamp(0.0, 1.0);

        // Update smoothed loss with EMA
        self.smoothed_loss = self.alpha * loss + (1.0 - self.alpha) * self.smoothed_loss;

        // Quadratic-gain proportional controller:
        //   power = error * |error| / target_loss
        // This gives aggressive adjustment far from target (fast ramp-up)
        // but very gentle adjustment near target (stable equilibrium).
        // At error=0 (equilibrium): power=0, adjustment=1 (no change)
        // At error=target (no loss): power=target, adjustment=base^target (~1.26 for base=2, target=0.33)
        // At error=target/10 (near target): power=target/100, adjustment≈1.002 (barely moves)
        let error = self.target_loss - self.smoothed_loss;
        let power = error * error.abs() / self.target_loss;
        let adjustment = self.base.powf(power);

        // Clamp adjustment to prevent wild swings
        let adjustment = adjustment.clamp(0.5, 4.0);

        self.rate *= adjustment;
        self.rate = self.rate.clamp(self.min_rate, self.max_rate);

        self.rate
    }

    /// Get current sending rate in packets per second
    pub fn rate(&self) -> f64 {
        self.rate
    }

    /// Get the smoothed observed loss rate
    #[allow(dead_code)]
    pub fn smoothed_loss(&self) -> f64 {
        self.smoothed_loss
    }

    /// Get the target loss rate
    #[allow(dead_code)]
    pub fn target_loss(&self) -> f64 {
        self.target_loss
    }

    /// Get the inter-packet interval in microseconds
    #[allow(dead_code)]
    pub fn interval_us(&self) -> u64 {
        if self.rate <= 0.0 {
            return 1_000_000;
        }
        (1_000_000.0 / self.rate) as u64
    }
}
