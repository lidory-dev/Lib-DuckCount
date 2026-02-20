use crate::cryptography::serializers::base64_serializer::base64_serializer;
use serde::{Deserialize, Serialize};

#[derive(uniffi::Record, Serialize, Deserialize)]
pub struct Group {
    pub uuid: String,
    #[serde(with = "base64_serializer")]
    pub master_key: Vec<u8>,
}
