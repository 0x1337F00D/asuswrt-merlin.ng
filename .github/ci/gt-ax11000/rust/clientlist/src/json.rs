//! Insertion-ordered JSON value.
//!
//! json-c 0.12.1 (`release/src/router/json-c/json_object.c:391-408`) keeps a
//! key at its original position when `json_object_object_add()` replaces an
//! existing value, and the Web UI compares polls with `JSON.stringify`, so the
//! emitted key order must be stable and match the C emission order. The
//! `serde_json` `Value` type sorts keys; this type keeps them ordered and is
//! read and written through `serde_json` with hand-written `serde` impls (no
//! derive macros are compiled).

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<Value>),
    Object(Object),
}

/// Insertion-ordered object with json-c replace-in-place semantics.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Object {
    entries: Vec<(String, Value)>,
}

impl Object {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// `json_object_object_add()`: replace an existing key in place, otherwise
    /// append.
    pub fn set(&mut self, key: &str, value: Value) {
        match self.entries.iter_mut().find(|(name, _)| name == key) {
            Some(entry) => entry.1 = value,
            None => self.entries.push((key.to_owned(), value)),
        }
    }

    pub fn set_str(&mut self, key: &str, value: &str) {
        self.set(key, Value::String(value.to_owned()));
    }

    /// Append without the replace lookup. Only for keys known to be absent.
    pub fn push(&mut self, key: &str, value: Value) {
        self.entries.push((key.to_owned(), value));
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.entries
            .iter()
            .map(|(name, value)| (name.as_str(), value))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&str, &mut Value)> {
        self.entries
            .iter_mut()
            .map(|(name, value)| (name.as_str(), value))
    }
}

impl Value {
    pub fn string(value: &str) -> Self {
        Value::String(value.to_owned())
    }

    pub fn int(value: i64) -> Self {
        Value::Number(serde_json::Number::from(value))
    }

    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Value::Object(object) => Some(object),
            _ => None,
        }
    }

    pub fn as_object_mut(&mut self) -> Option<&mut Object> {
        match self {
            Value::Object(object) => Some(object),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(array) => Some(array),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(text) => Some(text),
            _ => None,
        }
    }

    /// `json_object_get_string()` for a value that json-c would hand to
    /// `json_object_new_string()`: strings verbatim, numbers and booleans in
    /// their JSON spelling, containers as their JSON text. A JSON `null` is a
    /// NULL `json_object *` in json-c and would crash the C code; it becomes an
    /// empty string here.
    pub fn c_string(&self) -> String {
        match self {
            Value::Null => String::new(),
            Value::Bool(value) => value.to_string(),
            Value::Number(number) => number.to_string(),
            Value::String(text) => text.clone(),
            Value::Array(_) | Value::Object(_) => serde_json::to_string(self).unwrap_or_default(),
        }
    }
}

impl Serialize for Value {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Value::Null => serializer.serialize_unit(),
            Value::Bool(value) => serializer.serialize_bool(*value),
            Value::Number(number) => number.serialize(serializer),
            Value::String(text) => serializer.serialize_str(text),
            Value::Array(items) => {
                let mut sequence = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    sequence.serialize_element(item)?;
                }
                sequence.end()
            }
            Value::Object(object) => object.serialize(serializer),
        }
    }
}

impl Serialize for Object {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.entries.len()))?;
        for (key, value) in &self.entries {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

struct ValueVisitor;

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Ok(serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        Deserialize::deserialize(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut items = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(1_024));
        while let Some(item) = sequence.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut object = Object::with_capacity(map.size_hint().unwrap_or(0).min(1_024));
        while let Some((key, value)) = map.next_entry::<String, Value>()? {
            // The json-c tokener also replaces duplicate keys in place.
            object.set(&key, value);
        }
        Ok(Value::Object(object))
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(ValueVisitor)
    }
}

/// Parse a complete JSON document.
pub fn parse(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    serde_json::from_slice(bytes)
}

/// Serialize with the compact `serde_json` formatter.
pub fn to_string(value: &Value) -> Result<String, serde_json::Error> {
    serde_json::to_string(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_replaces_in_place_like_json_c() {
        let mut object = Object::new();
        object.set_str("type", "1");
        object.set_str("name", "a");
        object.set_str("type", "36");
        let keys: Vec<&str> = object.iter().map(|(key, _)| key).collect();
        assert_eq!(keys, ["type", "name"]);
        assert_eq!(object.get("type").and_then(Value::as_str), Some("36"));
    }

    #[test]
    fn round_trip_preserves_order_and_duplicate_key_position() {
        let value = parse(br#"{"z":1,"a":[true,null,1.5,"x"],"z":{"k":"v"}}"#).unwrap();
        assert_eq!(
            to_string(&value).unwrap(),
            r#"{"z":{"k":"v"},"a":[true,null,1.5,"x"]}"#
        );
    }

    #[test]
    fn c_string_matches_json_c_get_string() {
        assert_eq!(Value::int(31).c_string(), "31");
        assert_eq!(Value::Bool(true).c_string(), "true");
        assert_eq!(Value::string("x").c_string(), "x");
        assert_eq!(Value::Null.c_string(), "");
        assert_eq!(Value::Array(vec![Value::int(1)]).c_string(), "[1]");
    }

    #[test]
    fn rejects_invalid_documents() {
        assert!(parse(b"{").is_err());
        assert!(parse(b"\xff").is_err());
        assert!(parse(b"").is_err());
    }
}
