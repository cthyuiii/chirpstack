use std::fmt;
use std::str::FromStr;

use anyhow::Result;
#[cfg(feature = "postgres")]
use diesel::pg::Pg;
#[cfg(feature = "sqlite")]
use diesel::sqlite::Sqlite;
#[cfg(feature = "diesel")]
use diesel::{backend::Backend, deserialize, serialize, sql_types::Binary};
#[cfg(feature = "serde")]
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};

use crate::Error;

#[derive(Copy, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "diesel", derive(AsExpression, FromSqlRow))]
#[cfg_attr(feature = "diesel", diesel(sql_type = diesel::sql_types::Binary))]
pub struct AES256Key([u8; 32]);

impl AES256Key {
    pub fn null() -> Self {
        AES256Key([0; 32])
    }

    pub fn from_slice(b: &[u8]) -> Result<Self, Error> {
        if b.len() != 32 {
            return Err(Error::Aes256Length);
        }

        let mut bb: [u8; 32] = [0; 32];
        bb.copy_from_slice(b);

        Ok(AES256Key(bb))
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        AES256Key(b)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl fmt::Display for AES256Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for AES256Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for AES256Key {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes: [u8; 32] = [0; 32];
        if !s.is_empty() {
            hex::decode_to_slice(s, &mut bytes)?;
        }
        Ok(AES256Key(bytes))
    }
}

#[cfg(feature = "serde")]
impl Serialize for AES256Key {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for AES256Key {
    fn deserialize<D>(deserialize: D) -> Result<AES256Key, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize.deserialize_str(Aes256KeyVisitor)
    }
}

#[cfg(feature = "serde")]
struct Aes256KeyVisitor;

#[cfg(feature = "serde")]
impl Visitor<'_> for Aes256KeyVisitor {
    type Value = AES256Key;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("A hex encoded AES key of 256 bit is expected")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        AES256Key::from_str(value).map_err(|e| E::custom(format!("{}", e)))
    }
}

#[cfg(feature = "postgres")]
impl deserialize::FromSql<Binary, Pg> for AES256Key {
    fn from_sql(bytes: <Pg as Backend>::RawValue<'_>) -> deserialize::Result<Self> {
        let value = <Vec<u8> as deserialize::FromSql<Binary, Pg>>::from_sql(bytes)?;
        if value.len() != 32 {
            return Err("AES256Key type expects exactly 32 bytes".into());
        }

        let mut b = [0u8; 32];
        b.copy_from_slice(&value);
        Ok(AES256Key(b))
    }
}

#[cfg(feature = "postgres")]
impl serialize::ToSql<Binary, Pg> for AES256Key {
    fn to_sql<'b>(&'b self, out: &mut serialize::Output<'b, '_, Pg>) -> serialize::Result {
        <[u8] as serialize::ToSql<Binary, Pg>>::to_sql(&self.to_bytes(), &mut out.reborrow())
    }
}

#[cfg(feature = "sqlite")]
impl deserialize::FromSql<Binary, Sqlite> for AES256Key {
    fn from_sql(bytes: <Sqlite as Backend>::RawValue<'_>) -> deserialize::Result<Self> {
        let value = <Vec<u8> as deserialize::FromSql<Binary, Sqlite>>::from_sql(bytes)?;
        if value.len() != 32 {
            return Err("AES256Key type expects exactly 32 bytes".into());
        }

        let mut b = [0u8; 32];
        b.copy_from_slice(&value);
        Ok(AES256Key(b))
    }
}

#[cfg(feature = "sqlite")]
impl serialize::ToSql<Binary, Sqlite> for AES256Key {
    fn to_sql<'b>(&'b self, out: &mut serialize::Output<'b, '_, Sqlite>) -> serialize::Result {
        out.set_value(self.to_bytes().to_vec());
        Ok(serialize::IsNull::No)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_string() {
        let key = AES256Key::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
        ]);
        assert_eq!(
            "0102030405060708010203040506070801020304050607080102030405060708",
            key.to_string()
        );
    }

    #[test]
    fn test_from_str() {
        let key = AES256Key::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
        ]);
        assert_eq!(
            key,
            AES256Key::from_str("0102030405060708010203040506070801020304050607080102030405060708")
                .unwrap()
        );
        // a 16-byte (AES-128) key is refused
        assert!(AES256Key::from_str("01020304050607080102030405060708").is_err());
    }
}
