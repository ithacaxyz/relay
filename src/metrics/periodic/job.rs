use futures_util::future::poll_fn;
use jsonrpsee::core::async_trait;
use std::{fmt::Debug, future::Future, pin::Pin, sync::Arc, task::Poll};
use tokio::time::Interval;
use tracing::error;

use super::MetricCollector;

// Trait for a periodic job.
#[async_trait]
pub trait PeriodicMetricJob {
    /// Advances a periodic job.
    #[allow(unused)]
    async fn advance(&mut self);
}

// A periodic job that holds a collector and its period interval.
pub struct PeriodicJob<T> {
    /// Metric collector.
    collector: Arc<T>,
    /// Period interval that this collector should be run on.
    interval: Interval,
    /// Period interval that this collector should be run on.
    future: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl<T> PeriodicJob<T> {
    /// Creates a [PeriodicJob].
    pub fn new(collector: T, interval: Interval) -> Self {
        Self { collector: Arc::new(collector), interval, future: None }
    }
    /// Creates a new boxed [PeriodicJob].
    #[allow(unused)]
    pub fn new_boxed(collector: T, interval: Interval) -> Box<Self> {
        Box::new(Self::new(collector, interval))
    }
}

impl<T: MetricCollector> PeriodicJob<T> {
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

#[async_trait]
impl<T> PeriodicMetricJob for PeriodicJob<T>
where
    T: MetricCollector + Debug + Sync + Send + 'static,
{
    async fn advance(&mut self) {
        poll_fn(|cx| {
            if self.future.is_none() && self.interval.poll_tick(cx).is_ready() {
                let collector = self.collector.clone();
                self.future = Some(Box::pin(async move {
                    if let Err(err) = collector.collect().await {
                        error!(target = "metrics::periodic", ?err, ?collector);
                    }
                }));
            }

            if let Some(mut fut) = self.future.take() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(_) => {
                        return {
                            self.interval.reset();
                            Poll::Ready(())
                        }
                    }
                    Poll::Pending => self.future = Some(fut),
                }
            }

            Poll::Pending
        })
        .await
    }
}
