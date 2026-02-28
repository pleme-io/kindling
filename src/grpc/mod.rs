#[cfg(feature = "grpc")]
mod server;

#[cfg(feature = "grpc")]
pub use server::serve;
