use crate::error::WalletAbiError;
use crate::schema::bundle::{InputSchema, OutputSchema};
use lwk_wollet::elements::LockTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeParamsEnvelope {
    #[serde(default)]
    pub inputs: Vec<InputSchema>,
    #[serde(default)]
    pub outputs: Vec<OutputSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_rate_sat_vb: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locktime: Option<LockTime>,
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

impl RuntimeParamsEnvelope {
    pub fn from_request_params(value: &Value) -> Result<Self, WalletAbiError> {
        serde_json::from_value(value.clone())
            .map_err(|e| WalletAbiError::InvalidRequest(format!("invalid request params: {e}")))
    }

    pub fn to_request_params_value(&self) -> Result<Value, WalletAbiError> {
        serde_json::to_value(self).map_err(WalletAbiError::from)
    }
}
