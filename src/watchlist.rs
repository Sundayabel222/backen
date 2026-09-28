use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use serde::Deserialize;
use utoipa::ToSchema;

use crate::auth::AuthUser;
use crate::error::{db_error, AppError, AppJson};
use crate::models::WatchlistItem;
use crate::AppState;

#[utoipa::path(get, path = "/api/v1/watchlist", security(("bearerAuth" = [])), responses((status = 200, body = [WatchlistItem]), (status = 401, body = crate::error::ErrorResponse, description = "Unauthorized")))]
pub async fn get_watchlist(
    State(state): State<AppState>,
    AuthUser(wallet_address): AuthUser,
) -> Result<Json<Vec<WatchlistItem>>, AppError> {
    let items: Vec<WatchlistItem> =
        sqlx::query_as("SELECT * FROM watchlist WHERE wallet_address = ? ORDER BY added_at DESC")
            .bind(&wallet_address)
            .fetch_all(&state.db)
            .await
            .map_err(|e| db_error("load watchlist", e))?;

    Ok(Json(items))
}

#[derive(Deserialize, ToSchema)]
pub struct AddWatchlistRequest {
    pub underlying: String,
}

#[utoipa::path(post, path = "/api/v1/watchlist", request_body = AddWatchlistRequest, security(("bearerAuth" = [])), responses((status = 201, description = "Watchlist item added"), (status = 401, body = crate::error::ErrorResponse, description = "Unauthorized"), (status = 404, body = crate::error::ErrorResponse, description = "Unknown underlying")))]
pub async fn add_watchlist(
    State(state): State<AppState>,
    AuthUser(wallet_address): AuthUser,
    AppJson(req): AppJson<AddWatchlistRequest>,
) -> Result<StatusCode, AppError> {
    if !state
        .spot_prices
        .lock()
        .unwrap()
        .contains_key(&req.underlying)
    {
        return Err(AppError::new(
            StatusCode::NOT_FOUND,
            format!("unknown underlying \"{}\"", req.underlying),
        ));
    }

    sqlx::query(
        "INSERT INTO watchlist (wallet_address, underlying) VALUES (?, ?)
         ON CONFLICT(wallet_address, underlying) DO NOTHING",
    )
    .bind(&wallet_address)
    .bind(&req.underlying)
    .execute(&state.db)
    .await
    .map_err(|e| db_error("add watchlist item", e))?;

    Ok(StatusCode::CREATED)
}

#[utoipa::path(delete, path = "/api/v1/watchlist/{underlying}", params(("underlying" = String, Path, description = "Underlying symbol")), security(("bearerAuth" = [])), responses((status = 204, description = "Watchlist item removed"), (status = 401, body = crate::error::ErrorResponse, description = "Unauthorized"), (status = 404, body = crate::error::ErrorResponse, description = "Watchlist item not found")))]
pub async fn remove_watchlist(
    State(state): State<AppState>,
    AuthUser(wallet_address): AuthUser,
    Path(underlying): Path<String>,
) -> Result<StatusCode, AppError> {
    let result = sqlx::query("DELETE FROM watchlist WHERE wallet_address = ? AND underlying = ?")
        .bind(&wallet_address)
        .bind(&underlying)
        .execute(&state.db)
        .await
        .map_err(|e| db_error("remove watchlist item", e))?;

    if result.rows_affected() == 0 {
        return Err(AppError::new(
            StatusCode::NOT_FOUND,
            format!("\"{underlying}\" is not on this wallet's watchlist"),
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}
