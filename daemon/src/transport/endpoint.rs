use anyhow::Result;
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

/// Generates an in-memory self-signed certificate for the QUIC TLS handshake
fn generate_dummy_cert() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let keypair = rcgen::generate_simple_self_signed(vec!["decentis.local".into()])?;

    let cert_der = CertificateDer::from(keypair.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(keypair.signing_key.serialize_der())
        .map_err(|e| anyhow::anyhow!("Invalid private key: {:?}", e))?;

    Ok((vec![cert_der], key_der))
}

/// A custom certificate verifier that accepts any certificate
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

pub fn create_quic_endpoint(bind_addr: SocketAddr) -> Result<Endpoint> {
    info!("Generating ephemeral TLS certificate for QUIC...");
    let (cert_chain, key) = generate_dummy_cert()?;

    // Ensure the crypto provider is selected explicitly for rustls 0.23+
    let crypto_provider = rustls::crypto::ring::default_provider();

    // 1. Configure the Server (for incoming connections)
    let mut server_crypto =
        rustls::ServerConfig::builder_with_provider(Arc::new(crypto_provider.clone()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?;
    server_crypto.alpn_protocols = vec![b"decentis-mesh".to_vec()];

    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));

    // 2. Configure the Client (for outgoing connections)
    let client_crypto = rustls::ClientConfig::builder_with_provider(Arc::new(crypto_provider))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    let client_config_engine = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?;
    let mut client_config = ClientConfig::new(Arc::new(client_config_engine));

    // Enable RFC 9221 Unreliable Datagrams (Crucial for L3 VPN traffic)
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.datagram_receive_buffer_size(Some(65536));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    client_config.transport_config(Arc::new(transport_config));

    // 3. Bind the UDP socket and build the endpoint
    let mut endpoint = Endpoint::server(server_config, bind_addr)?;
    endpoint.set_default_client_config(client_config);

    info!("QUIC Endpoint successfully bound to UDP {}", bind_addr);

    Ok(endpoint)
}
