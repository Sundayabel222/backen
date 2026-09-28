use serde::Serialize;
use sqlx::FromRow;
use time::OffsetDateTime;
use utoipa::ToSchema;

pub fn now_utc_millis() -> OffsetDateTime {
    let now = OffsetDateTime::now_utc();
    now.replace_nanosecond((now.nanosecond() / 1_000_000) * 1_000_000)
        .expect("millisecond precision is within the valid nanosecond range")
}

#[derive(Debug, Clone, FromRow, Serialize, ToSchema)]
pub struct Account {
    pub wallet_address: String,
    pub balance: f64,
    pub collateral_locked: f64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, FromRow, Serialize, ToSchema)]
pub struct Position {
    pub id: String,
    pub wallet_address: String,
    pub underlying: String,
    pub strike: f64,
    pub expiry_days: f64,
    pub option_type: String,
    pub position_type: String,
    pub contracts: f64,
    pub entry_premium: f64,
    pub entry_spot: f64,
    pub collateral: f64,
    pub status: String,
    pub close_premium: Option<f64>,
    pub close_spot: Option<f64>,
    pub realized_pnl: Option<f64>,
    #[serde(with = "time::serde::rfc3339")]
    pub opened_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub closed_at: Option<OffsetDateTime>,
    pub strategy_id: Option<String>,
}

#[derive(Debug, Clone, FromRow, Serialize, ToSchema)]
pub struct WatchlistItem {
    pub wallet_address: String,
    pub underlying: String,
    #[serde(with = "time::serde::rfc3339")]
    pub added_at: OffsetDateTime,
}

#[derive(Debug, Clone, FromRow, Serialize, ToSchema)]
pub struct Alert {
    pub id: String,
    pub wallet_address: String,
    pub underlying: String,
    pub condition: String,
    pub target_price: f64,
    pub triggered: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub triggered_at: Option<OffsetDateTime>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_timestamps_are_utc_with_millisecond_precision() {
        let timestamp = now_utc_millis();
        assert_eq!(timestamp.offset(), time::UtcOffset::UTC);
        assert_eq!(timestamp.nanosecond() % 1_000_000, 0);
    }
}
