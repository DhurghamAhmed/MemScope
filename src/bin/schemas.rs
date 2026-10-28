use memscope::mcp::{MemScope, TOOL_NAMES};
use serde_json::Value;

fn pretty_schema(schema: &Value, indent: usize) -> Vec<String> {
    let pad = " ".repeat(indent);
    let mut out = Vec::new();
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return out;
    };
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|r| r.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    let mut names: Vec<&String> = properties.keys().collect();
    names.sort_by_key(|n| (!required.contains(&n.as_str()), (*n).clone()));

    for name in names {
        let field = &properties[name];
        let kind = describe_type(field);
        let marker = if required.contains(&name.as_str()) {
            "required"
        } else {
            "optional"
        };
        let description = field
            .get("description")
            .and_then(Value::as_str)
            .map(|d| {
                let single = d.split_whitespace().collect::<Vec<_>>().join(" ");
                format!(" — {single}")
            })
            .unwrap_or_default();
        out.push(format!(
            "{pad}| `{name}` | `{kind}` | {marker} |{description} |"
        ));
    }
    out
}

fn describe_type(field: &Value) -> String {
    if let Some(reference) = field.get("$ref").and_then(Value::as_str) {
        return reference.rsplit('/').next().unwrap_or(reference).to_owned();
    }
    if let Some(variants) = field.get("enum").and_then(Value::as_array) {
        let names: Vec<String> = variants
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        if !names.is_empty() {
            return names.join(" \\| ");
        }
    }
    if let Some(any_of) = field.get("anyOf").and_then(Value::as_array) {
        let parts: Vec<String> = any_of
            .iter()
            .filter(|v| v.get("type").and_then(Value::as_str) != Some("null"))
            .map(describe_type)
            .collect();
        if !parts.is_empty() {
            return format!("{} (nullable)", parts.join(" \\| "));
        }
    }
    match field.get("type") {
        Some(Value::String(t)) if t == "array" => {
            let inner = field
                .get("items")
                .map(describe_type)
                .unwrap_or_else(|| "any".to_owned());
            format!("array<{inner}>")
        }
        Some(Value::String(t)) => t.clone(),
        Some(Value::Array(types)) => types
            .iter()
            .filter_map(Value::as_str)
            .filter(|t| *t != "null")
            .collect::<Vec<_>>()
            .join(" \\| "),
        _ => "object".to_owned(),
    }
}

fn main() {
    let router = MemScope::tool_router();
    let mut tools = router.list_all();
    tools.sort_by_key(|t| {
        TOOL_NAMES
            .iter()
            .position(|n| *n == t.name.as_ref())
            .unwrap_or(usize::MAX)
    });

    println!("# MemScope tool schemas");
    println!();
    println!(
        "Generated from the live tool router by `cargo run --bin schemas`, so this file cannot"
    );
    println!("drift from the registered tools. {} tools.", tools.len());
    println!();
    println!("A tool failure arrives as a tool **result** with `is_error` set and structured");
    println!("content carrying `code`, `message`, `operation`, session and address context, the");
    println!("Win32 code when one exists, and a next step. Only an unroutable request is a");
    println!("JSON-RPC protocol error. See the error codes in README.md.");
    println!();

    for tool in &tools {
        println!("## `{}`", tool.name);
        println!();
        if let Some(description) = &tool.description {
            println!("{description}");
            println!();
        }
        let schema = serde_json::to_value(&tool.input_schema).unwrap_or(Value::Null);
        let rows = pretty_schema(&schema, 0);
        if rows.is_empty() {
            println!("Takes no parameters.");
        } else {
            println!("| Field | Type | Required | Notes |");
            println!("|---|---|---|---|");
            for row in rows {
                println!("{row}");
            }
        }
        println!();
        if let Some(output) = &tool.output_schema {
            let output = serde_json::to_value(output).unwrap_or(Value::Null);
            if output.get("properties").is_some() {
                println!("<details><summary>Output schema</summary>");
                println!();
                println!("```json");
                println!(
                    "{}",
                    serde_json::to_string_pretty(&output).unwrap_or_default()
                );
                println!("```");
                println!();
                println!("</details>");
                println!();
            }
        }
    }

    println!("## Shared value shapes");
    println!();
    println!("**`value_type`**: `int8`, `int16`, `int32`, `int64`, `uint8`, `uint16`, `uint32`,");
    println!("`uint64`, `float` (IEEE-754 binary32), `double` (binary64), `string` (UTF-8),");
    println!("`string16` (UTF-16LE), `bytes`, `pointer` (the target's width).");
    println!();
    println!("**`needle`** is tagged by `kind`:");
    println!();
    println!("```json");
    println!("{{ \"kind\": \"int\",   \"value\": \"-42\" }}");
    println!("{{ \"kind\": \"uint\",  \"value\": \"18446744073709551615\" }}");
    println!("{{ \"kind\": \"float\", \"value\": 0.1 }}");
    println!("{{ \"kind\": \"bytes\", \"hex\": \"cdcccc3d\" }}");
    println!("```");
    println!();
    println!("`int` and `uint` take **decimal strings** so no 64-bit value is lost to a JSON");
    println!("double. A JSON integer is accepted only when it is exactly representable.");
    println!();
    println!("**`payload`** for writes and freezes is tagged by `kind`:");
    println!();
    println!("```json");
    println!(
        "{{ \"kind\": \"typed\", \"value_type\": \"int32\", \"value\": {{ \"kind\": \"int\", \"value\": \"100\" }} }}"
    );
    println!("{{ \"kind\": \"bytes\", \"hex\": \"cd cc cc 3d\" }}");
    println!(
        "{{ \"kind\": \"text\",  \"value_type\": \"string\", \"text\": \"hi\", \"include_terminator\": false }}"
    );
    println!("```");
    println!();
    println!("A wildcard pattern is never a valid write payload.");
}
