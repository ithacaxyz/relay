//! OpenTelemetry configuration and initialization.

use std::str::FromStr;

use opentelemetry::{KeyValue, trace::TracerProvider};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{Resource, trace::SdkTracerProvider};
use opentelemetry_semantic_conventions::{
    SCHEMA_URL,
    attribute::{SERVICE_NAME, SERVICE_VERSION},
};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::Layer;
use url::Url;

/// An OpenTelemetry guard that manages the lifecycle of the tracer provider.
///
/// Once dropped, the tracer provider will be gracefully shut down.
#[derive(Debug)]
pub struct OtelGuard(SdkTracerProvider, tracing::Level);

impl OtelGuard {
    fn tracer(&self, s: &'static str) -> opentelemetry_sdk::trace::Tracer {
        self.0.tracer(s)
    }

    /// Adds a tracing layer to the given subscriber.
    pub fn layer<S>(&self) -> impl Layer<S>
    where
        S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
    {
        let tracer = self.tracer("relay");
        tracing_opentelemetry::layer()
            .with_tracer(tracer)
            .with_filter(LevelFilter::from_level(self.1))
    }
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Err(err) = self.0.shutdown() {
            eprintln!("{err:?}");
        }
    }
}

/// OpenTelemetry configuration.
#[derive(Debug, Clone)]
pub struct OtelConfig {
    /// Endpoint for the OpenTelemetry collector.
    pub endpoint: Url,
    /// Level filter for the OpenTelemetry traces.
    pub level: tracing::Level,
}

impl OtelConfig {
    /// Loads the OpenTelemetry configuration from environment variables.
    pub fn load() -> Option<Self> {
        let endpoint = std::env::var("OTEL_ENDPOINT").ok().and_then(|s| Url::parse(&s).ok())?;
        let level = std::env::var("OTEL_LEVEL")
            .ok()
            .and_then(|s| tracing::Level::from_str(&s).ok())
            .unwrap_or(tracing::Level::DEBUG);

        Some(Self { endpoint, level })
    }

    fn resource(&self) -> Resource {
        Resource::builder()
            .with_schema_url(
                [
                    KeyValue::new(SERVICE_NAME, env!("CARGO_PKG_NAME")),
                    KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
                ],
                SCHEMA_URL,
            )
            .build()
    }

    /// Creates an OpenTelemetry provider from this configuration.
    ///
    /// The returned [`OtelGuard`] is a guard that will shutdown the trace provider when dropped.
    pub fn provider(&self) -> OtelGuard {
        let exporter = opentelemetry_otlp::HttpExporterBuilder::default()
            .with_endpoint(self.endpoint.clone())
            .build_span_exporter()
            .unwrap();

        let provider = SdkTracerProvider::builder()
            .with_resource(self.resource())
            .with_batch_exporter(exporter)
            .build();

        OtelGuard(provider, self.level)
    }
}
