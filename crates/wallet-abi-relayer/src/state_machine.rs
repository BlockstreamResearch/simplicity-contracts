use thiserror::Error;
use wallet_abi_transport::wa_relay::{
    WalletAbiRelayDirection, WalletAbiRelayRole, WalletAbiRelayStatusState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageCounts {
    pub web_to_phone: u64,
    pub phone_to_web: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishTransition {
    pub next_state: String,
    pub status_events: Vec<WalletAbiRelayStatusState>,
}

#[derive(Debug, Error)]
pub enum StateMachineError {
    #[error("pairing is closed")]
    Closed,

    #[error("pairing is expired")]
    Expired,

    #[error("publish direction does not match authenticated role")]
    RoleDirectionMismatch,

    #[error("duplicate message for direction {0}")]
    DuplicateDirectionMessage(&'static str),

    #[error("response publish is only valid after request publish")]
    OutOfOrderResponse,

    #[error("pairing state '{0}' does not accept publishes")]
    InvalidState(String),
}

pub fn transition_on_peer_connected(current_state: &str) -> Option<String> {
    if current_state == "created" {
        Some("peer_connected".to_string())
    } else {
        None
    }
}

pub fn validate_publish(
    current_state: &str,
    role: WalletAbiRelayRole,
    direction: WalletAbiRelayDirection,
    counts: MessageCounts,
) -> Result<PublishTransition, StateMachineError> {
    if current_state == "closed" {
        return Err(StateMachineError::Closed);
    }
    if current_state == "expired" {
        return Err(StateMachineError::Expired);
    }

    if direction.expected_sender_role() != role {
        return Err(StateMachineError::RoleDirectionMismatch);
    }

    match direction {
        WalletAbiRelayDirection::WebToPhone => {
            if counts.web_to_phone > 0 {
                return Err(StateMachineError::DuplicateDirectionMessage("web_to_phone"));
            }

            if current_state != "created"
                && current_state != "peer_connected"
                && current_state != "request_sent"
            {
                return Err(StateMachineError::InvalidState(current_state.to_string()));
            }

            Ok(PublishTransition {
                next_state: "request_sent".to_string(),
                status_events: vec![WalletAbiRelayStatusState::RequestSent],
            })
        }
        WalletAbiRelayDirection::PhoneToWeb => {
            if counts.web_to_phone == 0 {
                return Err(StateMachineError::OutOfOrderResponse);
            }

            if counts.phone_to_web > 0 {
                return Err(StateMachineError::DuplicateDirectionMessage("phone_to_web"));
            }

            if current_state != "request_sent" {
                return Err(StateMachineError::InvalidState(current_state.to_string()));
            }

            Ok(PublishTransition {
                next_state: "closed".to_string(),
                status_events: vec![
                    WalletAbiRelayStatusState::ResponseSent,
                    WalletAbiRelayStatusState::Closed,
                ],
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_out_of_order_response_publish() {
        let result = validate_publish(
            "peer_connected",
            WalletAbiRelayRole::Phone,
            WalletAbiRelayDirection::PhoneToWeb,
            MessageCounts {
                web_to_phone: 0,
                phone_to_web: 0,
            },
        );

        assert!(matches!(result, Err(StateMachineError::OutOfOrderResponse)));
    }

    #[test]
    fn rejects_duplicate_request_message() {
        let result = validate_publish(
            "request_sent",
            WalletAbiRelayRole::Web,
            WalletAbiRelayDirection::WebToPhone,
            MessageCounts {
                web_to_phone: 1,
                phone_to_web: 0,
            },
        );

        assert!(matches!(
            result,
            Err(StateMachineError::DuplicateDirectionMessage("web_to_phone"))
        ));
    }

    #[test]
    fn accepts_happy_path_request_and_response() {
        let request = validate_publish(
            "peer_connected",
            WalletAbiRelayRole::Web,
            WalletAbiRelayDirection::WebToPhone,
            MessageCounts {
                web_to_phone: 0,
                phone_to_web: 0,
            },
        )
        .expect("request publish should pass");

        assert_eq!(request.next_state, "request_sent");
        assert_eq!(
            request.status_events,
            vec![WalletAbiRelayStatusState::RequestSent]
        );

        let response = validate_publish(
            &request.next_state,
            WalletAbiRelayRole::Phone,
            WalletAbiRelayDirection::PhoneToWeb,
            MessageCounts {
                web_to_phone: 1,
                phone_to_web: 0,
            },
        )
        .expect("response publish should pass");

        assert_eq!(response.next_state, "closed");
        assert_eq!(
            response.status_events,
            vec![
                WalletAbiRelayStatusState::ResponseSent,
                WalletAbiRelayStatusState::Closed
            ]
        );
    }
}
