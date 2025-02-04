use tokio::time::Interval;
use tracing::error;

use super::MetricCollector;

// A periodic job that holds a collector and its period interval.
pub struct PeriodicJob<T> {
    /// Metric collector.
    collector: T,
    /// Period interval that this collector should be run on.
    interval: Interval,
}

impl<T> PeriodicJob<T> {
    /// Creates a [PeriodicJob].
    pub fn new(collector: T, interval: Interval) -> Self {
        Self { collector, interval }
    }
}

impl<T: MetricCollector + 'static> PeriodicJob<T> {
    /// Launches a tokio task with a created [PeriodicJob].
    pub fn launch_task(collector: T, interval: Interval)
    where
        T: Send,
    {
        tokio::spawn(async move {
            let mut job = Self::new(collector, interval);
            loop {
                job.interval.tick().await;
                if let Err(err) = job.collector.collect().await {
                    error!(target = "metrics::periodic", ?err, ?job.collector);
                }
                job.interval.reset();
            }
        });
    }
}
