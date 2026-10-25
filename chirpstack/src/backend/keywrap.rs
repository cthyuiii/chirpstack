use anyhow::Result;
use tracing::trace;

use crate::config;
use backend::KeyEnvelope;
use lrwn::AES256Key;

pub fn unwrap(ke: &KeyEnvelope) -> Result<AES256Key> {
    // Nothing to unwrap
    if ke.kek_label.is_empty() {
        return Ok(AES256Key::from_slice(&ke.aes_key)?);
    }

    trace!(kek_label = %ke.kek_label, "Unwrapping AES key");
    let conf = config::get();

    for kek in &conf.keks {
        if kek.label == ke.kek_label {
            let key = ke.unwrap(&kek.kek.to_bytes())?;
            return Ok(AES256Key::from_bytes(key));
        }
    }

    Err(anyhow!("KEK label {} does not exist", ke.kek_label))
}

pub fn wrap(label: &str, key: AES256Key) -> Result<KeyEnvelope> {
    if label.is_empty() {
        return KeyEnvelope::new("", None, &key.to_bytes());
    }

    let conf = config::get();
    for kek in &conf.keks {
        if kek.label == *label {
            return KeyEnvelope::new(label, Some(&kek.kek.to_bytes()), &key.to_bytes());
        }
    }

    Err(anyhow!("KEK label {} does not exist", label))
}
