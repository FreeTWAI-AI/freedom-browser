use super::{error, internal};
use crate::{AppState, error::CanonicalError, error::RequestId};
use axum::{
    Extension, Json,
    extract::{State, rejection::JsonRejection},
    http::StatusCode,
};
use claw_api::models::{TelemetryState, UpdateTelemetryRequest};
use serde_json::Value;

pub(super) async fn telemetry(State(state): State<AppState>) -> Json<TelemetryState> {
    Json(to_contract_state(state.analytics.get_state().await))
}

pub(super) async fn update_telemetry(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Json<TelemetryState>, CanonicalError> {
    let Json(payload) = payload.map_err(|_| {
        error(
            &request_id,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "consent must be a boolean",
        )
    })?;
    // Freedom managed mode is fixed at process start. A settings write cannot
    // relax it, and a rejected write does not apply the consent change either.
    if state.freedom.is_managed() && crate::freedom::settings_try_to_relax(&payload) {
        return Err(error(
            &request_id,
            StatusCode::FORBIDDEN,
            crate::freedom::CODE_MODE_FIXED,
            "受管理的執行模式不能在執行中變更",
        ));
    }
    let request: UpdateTelemetryRequest = serde_json::from_value(payload).map_err(|_| {
        error(
            &request_id,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "consent must be a boolean",
        )
    })?;
    let telemetry = state
        .analytics
        .set_consent(request.consent)
        .await
        .map_err(|source| internal(&request_id, source))?;
    Ok(Json(to_contract_state(telemetry)))
}

fn to_contract_state(state: crate::analytics::TelemetryState) -> TelemetryState {
    TelemetryState::new(state.distinct_id, state.enabled, state.consent)
}
