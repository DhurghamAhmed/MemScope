use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{ErrorCode, OperationError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PointerWidth {
    Four,

    Eight,
}

impl PointerWidth {
    pub const fn bytes(self) -> usize {
        match self {
            Self::Four => 4,
            Self::Eight => 8,
        }
    }

    const fn hex_digits(self) -> usize {
        self.bytes() * 2
    }

    pub const fn max_address(self) -> u64 {
        match self {
            Self::Four => u32::MAX as u64,
            Self::Eight => u64::MAX,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetArch {
    X64,

    X86Wow64,
}

impl TargetArch {
    pub const fn pointer_width(self) -> PointerWidth {
        match self {
            Self::X64 => PointerWidth::Eight,
            Self::X86Wow64 => PointerWidth::Four,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X64 => "x64",
            Self::X86Wow64 => "x86_wow64",
        }
    }
}

impl fmt::Display for TargetArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(pub u64);

impl Address {
    pub fn to_canonical(self, width: PointerWidth) -> String {
        format!("0x{:0width$x}", self.0, width = width.hex_digits())
    }

    pub fn parse_hex(text: &str, operation: &str) -> Result<Self> {
        let trimmed = text.trim();
        let body = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        if body.is_empty() || !body.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                format!("address {text:?} is not canonical hexadecimal"),
            )
            .with_next_step("Supply the address as hex, for example 0x7ff6000012a0."));
        }
        u64::from_str_radix(body, 16).map(Address).map_err(|_| {
            OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                format!("address {text:?} does not fit in 64 bits"),
            )
            .with_next_step("Supply an address within the target's address space.")
        })
    }

    pub fn check_width(self, width: PointerWidth, operation: &str) -> Result<Self> {
        if self.0 > width.max_address() {
            return Err(OperationError::new(
                ErrorCode::UnsupportedPointerWidth,
                operation,
                format!(
                    "address 0x{:x} exceeds the {}-byte pointer width of this target",
                    self.0,
                    width.bytes()
                ),
            )
            .with_address(self.to_canonical(PointerWidth::Eight))
            .with_next_step("Use an address inside the 32-bit address space of a WOW64 target."));
        }
        Ok(self)
    }

    pub fn checked_add(self, delta: u64, operation: &str) -> Result<Self> {
        self.0.checked_add(delta).map(Address).ok_or_else(|| {
            OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                format!(
                    "address 0x{:x} + {delta} overflows a 64-bit address",
                    self.0
                ),
            )
            .with_next_step("Reduce the offset or size so the range stays addressable.")
        })
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WireI64(pub i64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WireU64(pub u64);

impl schemars::JsonSchema for WireI64 {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("Int64String")
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": ["string", "integer"],
            "description": "A signed 64-bit integer. Always emitted as a decimal string so no \
                            value is lost to a JSON double; a JSON integer is accepted on input \
                            only when it is exactly representable."
        })
    }
}

impl schemars::JsonSchema for WireU64 {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("Uint64String")
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": ["string", "integer"],
            "description": "An unsigned 64-bit integer. Always emitted as a decimal string so no \
                            value is lost to a JSON double; a JSON integer is accepted on input \
                            only when it is exactly representable."
        })
    }
}

impl Serialize for WireI64 {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}

impl Serialize for WireU64 {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for WireI64 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        match serde_json::Value::deserialize(d)? {
            serde_json::Value::String(s) => {
                s.trim().parse::<i64>().map(WireI64).map_err(|e| {
                    D::Error::custom(format!("int64 string {s:?} is not a 64-bit integer: {e}"))
                })
            }
            serde_json::Value::Number(n) => n
                .as_i64()
                .map(WireI64)
                .ok_or_else(|| D::Error::custom(format!(
                    "{n} cannot be carried exactly as an int64 JSON number; send it as a decimal string"
                ))),
            other => Err(D::Error::custom(format!(
                "expected an int64 decimal string, found {other}"
            ))),
        }
    }
}

impl<'de> Deserialize<'de> for WireU64 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        match serde_json::Value::deserialize(d)? {
            serde_json::Value::String(s) => {
                s.trim().parse::<u64>().map(WireU64).map_err(|e| {
                    D::Error::custom(format!("uint64 string {s:?} is not a 64-bit unsigned integer: {e}"))
                })
            }
            serde_json::Value::Number(n) => n
                .as_u64()
                .map(WireU64)
                .ok_or_else(|| D::Error::custom(format!(
                    "{n} cannot be carried exactly as a uint64 JSON number; send it as a decimal string"
                ))),
            other => Err(D::Error::custom(format!(
                "expected a uint64 decimal string, found {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FloatClass {
    Finite,
    Nan,
    Infinity,
    NegativeInfinity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FloatValue {
    pub class: FloatClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    pub repr: String,

    pub negative_zero: bool,
}

impl FloatValue {
    pub fn from_f32(v: f32) -> Self {
        Self::build(
            v.is_nan(),
            v.is_infinite(),
            v.is_sign_negative(),
            v == 0.0,
            f64::from(v),
            format!("{v}"),
        )
    }

    pub fn from_f64(v: f64) -> Self {
        Self::build(
            v.is_nan(),
            v.is_infinite(),
            v.is_sign_negative(),
            v == 0.0,
            v,
            format!("{v}"),
        )
    }

    fn build(
        is_nan: bool,
        is_inf: bool,
        is_neg: bool,
        is_zero: bool,
        widened: f64,
        repr: String,
    ) -> Self {
        let class = if is_nan {
            FloatClass::Nan
        } else if is_inf && is_neg {
            FloatClass::NegativeInfinity
        } else if is_inf {
            FloatClass::Infinity
        } else {
            FloatClass::Finite
        };
        Self {
            value: matches!(class, FloatClass::Finite).then_some(widened),
            repr,
            negative_zero: is_zero && is_neg,
            class,
        }
    }
}

pub fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

pub fn parse_hex_bytes(text: &str, operation: &str) -> Result<Vec<u8>> {
    let cleaned: String = text
        .trim()
        .strip_prefix("0x")
        .or_else(|| text.trim().strip_prefix("0X"))
        .unwrap_or(text.trim())
        .chars()
        .filter(|c| !matches!(c, ' ' | '_' | '-'))
        .collect();
    if cleaned.is_empty() {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            "byte string is empty",
        )
        .with_next_step("Supply at least one byte, for example \"cdcccc3d\"."));
    }
    if !cleaned.len().is_multiple_of(2) {
        return Err(OperationError::new(
            ErrorCode::InvalidArgument,
            operation,
            format!(
                "byte string has {} hex digits, which is not whole bytes",
                cleaned.len()
            ),
        )
        .with_next_step("Pad the value to an even number of hex digits."));
    }
    let bytes = cleaned.as_bytes();
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        let text = std::str::from_utf8(pair).expect("ascii hex filtered above");
        out.push(u8::from_str_radix(text, 16).map_err(|_| {
            OperationError::new(
                ErrorCode::InvalidArgument,
                operation,
                format!("{text:?} is not a hex byte"),
            )
            .with_next_step("Use only hex digits, optionally separated by spaces.")
        })?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_is_padded_to_the_targets_pointer_width() {
        let a = Address(0x12a0);
        assert_eq!(a.to_canonical(PointerWidth::Eight), "0x00000000000012a0");
        assert_eq!(a.to_canonical(PointerWidth::Four), "0x000012a0");
    }

    #[test]
    fn a_sixty_four_bit_address_is_refused_against_a_wow64_target() {
        let err = Address(0x7ff6_0000_12a0)
            .check_width(PointerWidth::Four, "read_memory")
            .expect_err("a 48-bit address cannot exist in a 32-bit target");
        assert_eq!(err.code, ErrorCode::UnsupportedPointerWidth);
    }

    #[test]
    fn a_decimal_address_is_refused_rather_than_guessed() {
        assert_eq!(Address::parse_hex("1000", "read_memory").unwrap().0, 0x1000);
        assert!(Address::parse_hex("", "read_memory").is_err());
        assert!(Address::parse_hex("0xzz", "read_memory").is_err());
    }

    #[test]
    fn an_overflowing_range_is_an_argument_error_not_a_wrapped_address() {
        let err = Address(u64::MAX - 3)
            .checked_add(8, "read_bytes")
            .expect_err("the range leaves the address space");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn a_sixty_four_bit_integer_crosses_the_wire_as_a_decimal_string() {
        let json = serde_json::to_string(&WireI64(i64::MIN)).unwrap();
        assert_eq!(json, "\"-9223372036854775808\"");
        let json = serde_json::to_string(&WireU64(u64::MAX)).unwrap();
        assert_eq!(json, "\"18446744073709551615\"");
    }

    #[test]
    fn a_lossy_json_number_is_refused_instead_of_being_rounded() {
        let ok: WireI64 = serde_json::from_str("42").unwrap();
        assert_eq!(ok.0, 42);

        let big: WireU64 = serde_json::from_str("\"18446744073709551615\"").unwrap();
        assert_eq!(big.0, u64::MAX);

        assert!(serde_json::from_str::<WireI64>("1.5").is_err());

        assert!(serde_json::from_str::<WireU64>("18446744073709551616").is_err());
    }

    #[test]
    fn binary32_one_tenth_round_trips_through_its_reported_repr() {
        let v = FloatValue::from_f32(0.1f32);
        assert_eq!(v.class, FloatClass::Finite);
        assert_eq!(v.repr, "0.1");
        assert_eq!(v.repr.parse::<f32>().unwrap(), 0.1f32);

        assert_eq!(hex(&0.1f32.to_le_bytes()), "cdcccc3d");
    }

    #[test]
    fn non_finite_floats_are_tagged_instead_of_emitted_as_invalid_json() {
        for (v, class) in [
            (f32::NAN, FloatClass::Nan),
            (f32::INFINITY, FloatClass::Infinity),
            (f32::NEG_INFINITY, FloatClass::NegativeInfinity),
        ] {
            let decoded = FloatValue::from_f32(v);
            assert_eq!(decoded.class, class);
            assert!(
                decoded.value.is_none(),
                "{class:?} must carry no JSON number"
            );
            let json = serde_json::to_string(&decoded).unwrap();

            let _: serde_json::Value = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn negative_zero_stays_distinguishable_from_positive_zero() {
        let neg = FloatValue::from_f64(-0.0);
        let pos = FloatValue::from_f64(0.0);
        assert!(neg.negative_zero);
        assert!(!pos.negative_zero);
        assert_eq!(neg.value, pos.value, "-0.0 == 0.0 as numbers");
    }

    #[test]
    fn hex_bytes_parse_with_or_without_separators() {
        assert_eq!(
            parse_hex_bytes("cd cc cc 3d", "write_memory").unwrap(),
            vec![0xcd, 0xcc, 0xcc, 0x3d]
        );
        assert_eq!(
            parse_hex_bytes("0xCDCCCC3D", "write_memory").unwrap(),
            vec![0xcd, 0xcc, 0xcc, 0x3d]
        );
        assert!(parse_hex_bytes("cdc", "write_memory").is_err());
        assert!(parse_hex_bytes("", "write_memory").is_err());
    }
}
