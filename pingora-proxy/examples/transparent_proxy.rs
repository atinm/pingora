// Copyright 2024 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::time::Duration;

use async_trait::async_trait;
use clap::Parser;
use log::info;
use pingora_core::listeners::tls::TlsSettings;
use prometheus::register_int_counter;

use pingora_core::{protocols::ALPN, server::configuration::Opt};
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::{Error, Result};
use pingora_proxy::{ProxyHttp, Session};

pub struct MyProxy {
    req_metric: prometheus::IntCounter,
}

pub struct MyCtx {
    tries: usize,
}

#[async_trait]
impl ProxyHttp for MyProxy {
    type CTX = MyCtx;
    fn new_ctx(&self) -> Self::CTX {
        MyCtx { tries: 0 }
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut e: Box<Error>,
    ) -> Box<Error> {
        if ctx.tries > 0 {
            return e;
        }
        ctx.tries += 1;
        e.set_retry(true);
        e
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let host = session.req_header().uri.host().unwrap().to_string();
        
        let addr = (host.clone(), 443);

        info!("connecting to {addr:?}");

        let mut peer = HttpPeer::new(addr, true, host);
        peer.options.alpn = ALPN::H2H1;
        peer.options.connection_timeout = Some(Duration::from_millis(100));

        let peer = Box::new(peer);
        Ok(peer)
    }

    async fn logging(
        &self,
        session: &mut Session,
        _e: Option<&pingora_core::Error>,
        ctx: &mut Self::CTX,
    ) {
        let response_code = session
            .response_written()
            .map_or(0, |resp| resp.status.as_u16());
        info!(
            "{} response code: {response_code}",
            self.request_summary(session, ctx)
        );

        self.req_metric.inc();
    }
}

#[cfg(feature = "openssl_derived")]
mod boringssl_openssl {
    use std::fs::File;
    use std::io::{BufReader, Read};

    use super::*;
    use pingora_core::tls::{pkey::PKey, ssl};
    use pingora_core::tls::x509::X509;
    use rcgen::{
        Certificate, CertificateParams, DistinguishedName, IsCa, KeyPair, SanType,
        KeyUsagePurpose
    };

    pub(super) struct DynamicCert {
        cert: Certificate
    }

    impl DynamicCert {
        /// Generates a new CA certificate and private key.
        ///
        /// # Returns
        ///
        /// The `Certificate` object for the new CA.

        fn create_ca_cert() -> Certificate {
            let key_pair = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();

            let mut dn = DistinguishedName::new();
            dn.push(rcgen::DnType::CommonName, "My SSE Proxy CA".to_string());
            dn.push(rcgen::DnType::OrganizationName, "My SSE Proxy Organization Name".to_string());
            dn.push(rcgen::DnType::OrganizationalUnitName, "My SSE Proxy Organization Unit Name".to_string());

            let mut params = CertificateParams::default();
            params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.distinguished_name = dn;
            params.key_pair = Some(key_pair);
            params.not_before = time::OffsetDateTime::now_utc();
            params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365 * 20);

            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

            let cert = Certificate::from_params(params).unwrap();

            let cert_pem = cert.serialize_pem().unwrap();
            let path = format!("{}/tests/certs", env!("CARGO_MANIFEST_DIR"));
            let cert_path = format!("{}/tests/certs/myrootca.pem", env!("CARGO_MANIFEST_DIR"));
            let key_path = format!("{}/tests/certs/myrootca.key", env!("CARGO_MANIFEST_DIR"));

            std::fs::create_dir_all(path).unwrap();
            std::fs::write(cert_path, &cert_pem.as_bytes()).unwrap();
            std::fs::write(key_path, &cert.serialize_private_key_pem().as_bytes()).unwrap();
            cert
        }

        /// Reads an existing CA certificate and private key from the specified PEM files.
        ///
        /// # Arguments
        ///
        /// * `ca_path` - The path to the CA file without any extension (e.g. "certs/rootca").
        ///
        /// # Returns
        ///
        /// The `Certificate` object for the CA, or an error if the PEM files could not be read or parsed.
        pub fn read_root_cert(ca_path: String) -> Result<Certificate, Box<dyn std::error::Error>> {
            // Open the PEM file containing both the certificate and private key

            let pem_cert_file = File::open(format!("{ca_path}.pem"))?;
            let mut pem_cert_reader = BufReader::new(pem_cert_file);

            let mut cert_string = String::new();
            pem_cert_reader.read_to_string(&mut cert_string)?;

            let pem_key_file = File::open(format!("{ca_path}.key"))?;
            let mut pem_key_reader = BufReader::new(pem_key_file);

            let mut key_pair_sting = String::new();
            pem_key_reader.read_to_string(&mut key_pair_sting)?;

            let key_pair = KeyPair::from_pem(key_pair_sting.as_str())?;

            // Parse the PEM file and create a new CertificateParams object
            let ca_cert_params = CertificateParams::from_ca_cert_pem(cert_string.as_str(), key_pair)?;

            // Create a new certificate using the CertificateParams object
            let ca_cert = Certificate::from_params(ca_cert_params)?;

            Ok(ca_cert)
        }

        /// Generates a new SSL certificate and private key signed by the specified CA.
        ///
        /// # Arguments
        ///
        /// * `ca_cert` - The `Certificate` object for the CA to sign the new certificate with.
        /// * `dn_name` - The domain name to generate the certificate for.
        fn signed_cert_with_ca(ca_cert: &Certificate, dn_name: String) -> Certificate {
            let mut dn = DistinguishedName::new();
            dn.push(rcgen::DnType::CommonName, dn_name.clone());
            dn.push(rcgen::DnType::OrganizationName, "My SSE Proxy Organization Name".to_string());
            dn.push(rcgen::DnType::OrganizationalUnitName, "My SSE Proxy Organization Unit Name".to_string());

            let mut params = CertificateParams::default();

            params.distinguished_name = dn;
            params.not_before = time::OffsetDateTime::now_utc();
            params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365 * 20);

            params.subject_alt_names = vec![
                SanType::DnsName(dn_name.clone()),
                SanType::DnsName(String::from("localhost")),
                SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
                SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                    0, 0, 0, 0, 0, 0, 0, 1,
                ))),
            ];
            let cert = Certificate::from_params(params).unwrap();
            let cert_signed = cert.serialize_pem_with_signer(&ca_cert).unwrap();
            let path = format!("{}/tests/certs", env!("CARGO_MANIFEST_DIR"));
            let cert_path = format!("{}/tests/certs/{dn_name}.pem", env!("CARGO_MANIFEST_DIR"));
            let key_path = format!("{}/tests/certs/{dn_name}.key", env!("CARGO_MANIFEST_DIR"));
        
            std::fs::create_dir_all(path).unwrap();
            std::fs::write(cert_path, cert_signed).unwrap();
            std::fs::write(key_path, &cert.serialize_private_key_pem().as_bytes()).unwrap();
            cert
        }

        pub(super) fn new(cert_path: &str) -> Box<Self> {
            let ca_cert: Certificate;
            if cert_path == String::from("new") {
                ca_cert = Self::create_ca_cert();
            } else {
                match Self::read_root_cert(cert_path.to_string()) {
                    Ok(cert) => {
                        info!("Successfully read CA:");
                        ca_cert = cert;
                    }
                    Err(_err) => {
                        ca_cert = Self::create_ca_cert();
                    }
                }
            }
            Box::new(DynamicCert { cert: ca_cert })
        }
    }

    #[async_trait]
    impl pingora_core::listeners::TlsAccept for DynamicCert {
        async fn certificate_callback(&self, ssl: &mut pingora_core::tls::ssl::SslRef) {
            use pingora_core::tls::ext;
            let sni = ssl.servername(ssl::NameType::HOST_NAME).unwrap();
            info!("sni: {sni}");
            let cert = Self::signed_cert_with_ca(&self.cert, sni.to_string());
            let cert_signed = cert.serialize_pem_with_signer(&self.cert).unwrap();
            ext::ssl_use_certificate(ssl, &X509::from_pem(&cert_signed.as_bytes()).unwrap()).unwrap();
            ext::ssl_use_private_key(ssl, &PKey::private_key_from_pem(&cert.serialize_private_key_pem().as_bytes()).unwrap()).unwrap();
        }
    }
}
// RUST_LOG=DEBUG cargo run --example transparent_proxy
// curl -kv --resolve '*:443:127.0.0.1' 'https://s.yimg.com/aaq/wf/wf-fetch-1.19.1-modern.js' \
//  -H 'sec-ch-ua-platform: "macOS"' \
//  -H 'Referer: https://www.yahoo.com/' \
//  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36' \
//  -H 'sec-ch-ua: "Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"' \
//  -H 'sec-ch-ua-mobile: ?0'
// For metrics
// curl 127.0.0.1:6192/
fn main() {
    env_logger::init();

    // read command line arguments
    let opt = Opt::parse();
    let mut my_server = Server::new(Some(opt)).unwrap();
    my_server.bootstrap();

    let mut my_proxy = pingora_proxy::http_proxy_service(
        &my_server.configuration,
        MyProxy {
            req_metric: register_int_counter!("req_counter", "Number of requests").unwrap(),
        },
    );
    let cert_path = format!("{}/tests/certs/myrootca", env!("CARGO_MANIFEST_DIR"));
    let mut tls_settings;

    // NOTE: dynamic certificate callback is only supported with BoringSSL/OpenSSL
    #[cfg(feature = "openssl_derived")]
    {
        let dynamic_cert = boringssl_openssl::DynamicCert::new(&cert_path);
        tls_settings = TlsSettings::with_callbacks(dynamic_cert).unwrap();
    }
    #[cfg(feature = "rustls")]
    {
        tls_settings = TlsSettings::intermediate(&cert_path, &key_path).unwrap();
    }
    #[cfg(not(feature = "any_tls"))]
    {
        tls_settings = TlsSettings;
    }
    tls_settings.enable_h2();
    my_proxy.add_tls_with_settings("127.0.0.1:8443", None, tls_settings);
    my_server.add_service(my_proxy);

    let mut prometheus_service_http =
        pingora_core::services::listening::Service::prometheus_http_service();
    prometheus_service_http.add_tcp("127.0.0.1:6192");
    my_server.add_service(prometheus_service_http);

    my_server.run_forever();
}
