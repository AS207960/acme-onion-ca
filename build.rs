fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .type_attribute(".", "#[derive(Serialize, Deserialize)]")
        .type_attribute(".", "#[serde(rename_all = \"camelCase\")]")
        .extern_path(
            ".google.protobuf.Any",
            "::prost_wkt_types::Any"
        )
        .extern_path(
            ".google.protobuf.Timestamp",
            "::prost_wkt_types::Timestamp"
        )
        .extern_path(
            ".google.protobuf.Value",
            "::prost_wkt_types::Value"
        )
        .compile(&["proto/order.proto"], &["proto/"]).unwrap();
    Ok(())
}