use crate::schema::expression::RefExpression;

use std::fmt;

use simplicityhl::ResolvedType;
use simplicityhl::parse::ParseFromStr;

use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgumentValue {
    Argument(simplicityhl::Value),
    Ref(RefExpression),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessValue {
    Witness(simplicityhl::Value),
    Ref(RefExpression),
}

#[derive(Debug, Clone, Copy)]
enum BindingKind {
    Argument,
    Witness,
}

impl BindingKind {
    const fn kind_name(self) -> &'static str {
        match self {
            Self::Argument => "argument value",
            Self::Witness => "witness value",
        }
    }

    const fn value_variant_name(self) -> &'static str {
        match self {
            Self::Argument => "Argument",
            Self::Witness => "Witness",
        }
    }
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum BindingField {
    Ref,
    Value,
    Type,
}

fn serialize_binding<S: Serializer>(
    value: &simplicityhl::Value,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut map = serializer.serialize_map(Some(2))?;
    map.serialize_entry("value", &value.to_string())?;
    map.serialize_entry("type", &value.ty().to_string())?;
    map.end()
}

fn serialize_ref_binding<S: Serializer>(
    reference: &RefExpression,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut map = serializer.serialize_map(Some(1))?;
    map.serialize_entry("ref", &reference.reference)?;
    map.end()
}

fn parse_ref_or_value_binding<'de, D: Deserializer<'de>>(
    deserializer: D,
    kind: BindingKind,
) -> Result<(Option<RefExpression>, Option<simplicityhl::Value>), D::Error> {
    struct BindingVisitor {
        kind: BindingKind,
    }

    impl<'de> Visitor<'de> for BindingVisitor {
        type Value = (Option<RefExpression>, Option<simplicityhl::Value>);

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "{} object with either {{\"ref\": ...}} or {{\"value\": ..., \"type\": ...}}",
                self.kind.kind_name()
            )
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut reference: Option<String> = None;
            let mut value: Option<String> = None;
            let mut ty: Option<String> = None;

            while let Some(key) = map.next_key::<BindingField>()? {
                match key {
                    BindingField::Ref => {
                        if reference.is_some() {
                            return Err(de::Error::duplicate_field("ref"));
                        }
                        reference = Some(map.next_value()?);
                    }
                    BindingField::Value => {
                        if value.is_some() {
                            return Err(de::Error::duplicate_field("value"));
                        }
                        value = Some(map.next_value()?);
                    }
                    BindingField::Type => {
                        if ty.is_some() {
                            return Err(de::Error::duplicate_field("type"));
                        }
                        ty = Some(map.next_value()?);
                    }
                }
            }

            match (reference, value, ty) {
                (Some(reference), None, None) => Ok((Some(RefExpression { reference }), None)),
                (None, Some(value_str), Some(type_str)) => {
                    let resolved_type =
                        ResolvedType::parse_from_str(&type_str).map_err(|error| {
                            de::Error::custom(format!(
                                "invalid {} type '{}': {error}",
                                self.kind.kind_name(),
                                type_str
                            ))
                        })?;

                    let parsed_value =
                        simplicityhl::Value::parse_from_str(&value_str, &resolved_type).map_err(
                            |error| {
                                de::Error::custom(format!(
                                    "invalid {} value '{}' for type '{}': {error}",
                                    self.kind.kind_name(),
                                    value_str,
                                    type_str
                                ))
                            },
                        )?;

                    Ok((None, Some(parsed_value)))
                }
                (Some(_), Some(_), _) | (Some(_), _, Some(_)) => Err(de::Error::custom(format!(
                    "{} must not contain both 'ref' and 'value'/'type'",
                    self.kind.kind_name()
                ))),
                (None, Some(_), None) => Err(de::Error::custom(format!(
                    "{} with 'value' must also include 'type'",
                    self.kind.kind_name()
                ))),
                (None, None, Some(_)) => Err(de::Error::custom(format!(
                    "{} with 'type' must also include 'value'",
                    self.kind.kind_name()
                ))),
                (None, None, None) => Err(de::Error::custom(format!(
                    "{} must include either 'ref' or both 'value' and 'type'",
                    self.kind.kind_name()
                ))),
            }
        }
    }

    deserializer.deserialize_map(BindingVisitor { kind })
}

impl Serialize for ArgumentValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Argument(value) => serialize_binding(value, serializer),
            Self::Ref(reference) => serialize_ref_binding(reference, serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ArgumentValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (reference, value) = parse_ref_or_value_binding(deserializer, BindingKind::Argument)?;
        if let Some(reference) = reference {
            return Ok(Self::Ref(reference));
        }
        if let Some(value) = value {
            return Ok(Self::Argument(value));
        }
        Err(de::Error::custom(format!(
            "{} must resolve to '{}' or '{}'",
            BindingKind::Argument.kind_name(),
            BindingKind::Argument.value_variant_name(),
            "Ref"
        )))
    }
}

impl Serialize for WitnessValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Witness(value) => serialize_binding(value, serializer),
            Self::Ref(reference) => serialize_ref_binding(reference, serializer),
        }
    }
}

impl<'de> Deserialize<'de> for WitnessValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (reference, value) = parse_ref_or_value_binding(deserializer, BindingKind::Witness)?;
        if let Some(reference) = reference {
            return Ok(Self::Ref(reference));
        }
        if let Some(value) = value {
            return Ok(Self::Witness(value));
        }
        Err(de::Error::custom(format!(
            "{} must resolve to '{}' or '{}'",
            BindingKind::Witness.kind_name(),
            BindingKind::Witness.value_variant_name(),
            "Ref"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argument_value_roundtrip_ref() {
        let value = ArgumentValue::Ref(RefExpression {
            reference: "params.arguments.foo".to_string(),
        });
        let json = serde_json::to_value(&value).expect("serialize");
        assert_eq!(json, serde_json::json!({ "ref": "params.arguments.foo" }));

        let decoded: ArgumentValue = serde_json::from_value(json).expect("deserialize");
        assert_eq!(decoded, value);
    }

    #[test]
    fn witness_value_roundtrip_constant() {
        let value = WitnessValue::Witness(simplicityhl::Value::from(false));
        let json = serde_json::to_value(&value).expect("serialize");
        assert_eq!(
            json,
            serde_json::json!({
                "value": "false",
                "type": "bool"
            })
        );

        let decoded: WitnessValue = serde_json::from_value(json).expect("deserialize");
        assert_eq!(decoded, value);
    }

    #[test]
    fn argument_value_rejects_mixed_ref_and_value_keys() {
        let err = serde_json::from_value::<ArgumentValue>(serde_json::json!({
            "ref": "params.a",
            "value": "1",
            "type": "u8"
        }))
        .expect_err("mixed keys must fail");
        let message = err.to_string();
        assert!(message.contains("must not contain both 'ref' and 'value'/'type'"));
    }

    #[test]
    fn witness_value_rejects_missing_type() {
        let err = serde_json::from_value::<WitnessValue>(serde_json::json!({
            "value": "1"
        }))
        .expect_err("value without type must fail");
        let message = err.to_string();
        assert!(message.contains("with 'value' must also include 'type'"));
    }

    #[test]
    fn argument_value_rejects_unknown_key() {
        let err = serde_json::from_value::<ArgumentValue>(serde_json::json!({
            "foo": "bar"
        }))
        .expect_err("unknown key must fail");
        let message = err.to_string();
        assert!(message.contains("unknown field `foo`"));
    }
}
