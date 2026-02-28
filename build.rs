fn main() {
    #[cfg(feature = "grpc")]
    {
        tonic_build::compile_protos("proto/kindling.proto")
            .expect("Failed to compile protobuf");
    }
}
