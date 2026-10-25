use rand::Rng;

use lrwn::AES256Key;

pub fn get_random_aes_key() -> AES256Key {
    let mut rng = rand::rng();
    let mut key: [u8; 32] = [0; 32];
    rng.fill_bytes(&mut key);
    AES256Key::from_bytes(key)
}
