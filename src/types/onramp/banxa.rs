//! Banxa onramp.

use alloy::primitives::B256;
use serde::{Deserialize, Serialize};

use super::{OnrampCountry, OrderId, PaymentMethod};

/// A Banxa buy quote.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuyQuote {
    /// The payment method.
    pub payment_method: PaymentMethod,
    /// The crypto amount.
    pub crypto_amount: f32,
    /// The price of the crypto in fiat.
    pub fiat_amount: f32,
    /// The processing fee in fiat.
    pub processing_fee: f32,
    /// The network fee in fiat.
    pub network_fee: f32,
}

/// Banxa order status.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OrderStatus {
    /// Order has been created and the customer has submitted KYC information.
    ///
    /// For Buy orders, this indicates we are waiting for customer to make payment for the order.
    ///
    /// For Sell orders, this indicates we are waiting for the required conditions to be met before
    /// we can accept the crypto payment.
    PendingPayment,
    /// For Buy orders, this indicates that the Customer has submitted their payment information,
    /// and we are now waiting for final payment confirmation from any external payment systems.
    ///
    /// For Sell orders, this indicates that all the required conditions have been met and we are
    /// waiting for the Customer to make the crypto payment to the wallet address provided. This
    /// status occurs when the customer has passed KYC verification and submitted their Bank Account
    /// details for receiving fiat. This webhook will notify you that cryptocurrency is ready to be
    /// sent to Banxa.
    WaitingPayment,
    /// Customer has made payment and payment has been confirmed.
    ///
    ///  For Buy orders, payment refers to fiat currency.
    ///
    ///  For Sell orders, payment refers to crypto currency.
    PaymentReceived,
    /// Payment information has been received by the external payment systems. The order is now in
    /// final verification and processing.
    InProgress,
    /// Cryptocurrency transaction has been submitted blockchain.
    CryptoTransferred,
    /// Order has been cancelled by Banxa due to internal risk and compliance alerts.
    Cancelled,
    /// Order has been declined by external payment systems.
    Declined,
    /// Order has been created, customer has not made payment for the order within the expiry time.
    /// (Expiry times may differ for each payment method)
    Expired,
    /// Order has been completed.
    ///
    /// For Buy orders, we deem the cryptocurrency transaction to be completed after 2
    /// confirmations on blockchain.
    ///
    /// For Sell orders, we deem the fiat payout to be completed when the fiat currency has been
    /// successfully sent.
    Complete,
    /// Order has been refunded by Banxa customer support in response to a request from the
    /// customer.
    Refunded,
    /// The order has been held for extra verification such as ID address verification. Banxa
    /// customer support will be reaching out to the customer to assist them resolve the order.
    ExtraVerification,
}

impl From<OrderStatus> for super::OrderStatus {
    fn from(status: OrderStatus) -> Self {
        match status {
            OrderStatus::PendingPayment
            | OrderStatus::WaitingPayment
            | OrderStatus::PaymentReceived
            | OrderStatus::InProgress => Self::PaymentPending,
            OrderStatus::CryptoTransferred => Self::TxSubmitted,
            OrderStatus::Cancelled => Self::Cancelled,
            OrderStatus::Declined => Self::PaymentDeclined,
            OrderStatus::Expired => Self::Expired,
            OrderStatus::Complete => Self::Completed,
            OrderStatus::Refunded => Self::Refunded,
            OrderStatus::ExtraVerification => Self::VerificationPending,
        }
    }
}

/// A Banxa order.
///
/// # Note
///
/// This is non-exhaustive; we ignore some fields we do not care about.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    /// The order ID.
    pub id: OrderId,
    /// The country the customer who placed the order is in.
    pub country: OnrampCountry,
    /// The transaction hash on the destination chain.
    pub transaction_hash: Option<B256>,
    /// The order status.
    pub status: OrderStatus,
}
