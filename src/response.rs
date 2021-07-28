use crate::jwt::{Token, TokenMetaData};
use rocket::http::{ContentType, Status};
use rocket::serde::json::Json;
use rocket::serde::Serialize;

// for token, refresh
#[derive(Serialize, Debug, Clone)]
pub enum TokenResponseBody {
  Access(TokenResponse),
  Error(MessageResponse),
}

// for create_user
#[derive(Serialize, Debug, Clone)]
pub enum MessageResponseBody {
  Access(MessageResponse),
  Error(MessageResponse),
}

#[derive(Serialize, Debug, Clone)]
pub struct TokenResponse {
  pub token: Token,
  pub metadata: TokenMetaData,
  pub message: String,
}
#[derive(Serialize, Debug, Clone)]
pub struct MessageResponse {
  pub message: String,
}

pub fn message_response_error(
  status: Status,
) -> (Status, (ContentType, Json<MessageResponseBody>)) {
  (
    status,
    (
      ContentType::JSON,
      Json(MessageResponseBody::Error(MessageResponse {
        message: status.to_string(),
      })),
    ),
  )
  // match status.code {
  //   503 => (
  //     Status::new(503),
  //     (
  //       ContentType::JSON,
  //       Json(MessageResponseBody::Error(MessageResponse {
  //         message: "Server Fail".to_string(),
  //       })),
  //     ),
  //   ),
  //   403 => (
  //     Status::new(403),
  //     (
  //       ContentType::JSON,
  //       Json(MessageResponseBody::Error(MessageResponse {
  //         message: "Authentication Error".to_string(),
  //       })),
  //     ),
  //   ),
  //   _ => (
  //     Status::new(400),
  //     (
  //       ContentType::JSON,
  //       Json(MessageResponseBody::Error(MessageResponse {
  //         message: "Bad Request".to_string(),
  //       })),
  //     ),
  //   ),
  // }
}

pub fn token_response_error(status: Status) -> (Status, (ContentType, Json<TokenResponseBody>)) {
  (
    status,
    (
      ContentType::JSON,
      Json(TokenResponseBody::Error(MessageResponse {
        message: status.to_string(),
      })),
    ),
  )
  // match status.code {
  //   400 => (
  //     Status::new(500),
  //     (
  //       ContentType::JSON,
  //       Json(TokenResponseBody::Error(MessageResponse {
  //         message: "Server Fail".to_string(),
  //       })),
  //     ),
  //   ),
  //   403 => (
  //     Status::new(403),
  //     (
  //       ContentType::JSON,
  //       Json(TokenResponseBody::Error(MessageResponse {
  //         message: "Authentication Error".to_string(),
  //       })),
  //     ),
  //   ),
  //   _ => (
  //     Status::new(400),
  //     (
  //       ContentType::JSON,
  //       Json(TokenResponseBody::Error(MessageResponse {
  //         message: "Bad Request".to_string(),
  //       })),
  //     ),
  //   ),
  // }
}
