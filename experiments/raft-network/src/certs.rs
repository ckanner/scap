//! Ephemeral test certificates. No test or production private keys are stored
//! in this repository or emitted in evidence logs.
use std::fs;
use std::path::Path;

use rcgen::{
    date_time_ymd, BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use scap_raft_transport::{ClientSecurity, PeerEndpoint, ServerSecurity};
use scap_raft_wire::{certificate_identity, Binding};

use crate::common::CLUSTER;

#[derive(Clone)]
pub struct Material {
    pub certificate: Vec<u8>,
    pub key: Vec<u8>,
    pub der: Vec<u8>,
}

impl Material {
    pub fn client(&self, ca: &[u8]) -> ClientSecurity {
        ClientSecurity {
            certificate_pem: self.certificate.clone(),
            private_key_pem: self.key.clone(),
            server_ca_pem: ca.to_vec(),
        }
    }

    pub fn server(&self, ca: &[u8]) -> ServerSecurity {
        ServerSecurity {
            certificate_pem: self.certificate.clone(),
            private_key_pem: self.key.clone(),
            client_ca_pem: ca.to_vec(),
        }
    }

    pub fn binding(&self, node_id: u64) -> Binding {
        Binding {
            node_id,
            fingerprint: certificate_identity(&self.der, 16 * 1024)
                .unwrap()
                .fingerprint,
        }
    }

    pub fn write(&self, directory: &Path, name: &str) {
        fs::write(directory.join(format!("{name}.pem")), &self.certificate).unwrap();
        fs::write(directory.join(format!("{name}.key")), &self.key).unwrap();
        fs::write(directory.join(format!("{name}.der")), &self.der).unwrap();
    }

    pub fn load(directory: &Path, name: &str) -> Self {
        Self {
            certificate: fs::read(directory.join(format!("{name}.pem"))).unwrap(),
            key: fs::read(directory.join(format!("{name}.key"))).unwrap(),
            der: fs::read(directory.join(format!("{name}.der"))).unwrap(),
        }
    }
}

pub struct Authority {
    certificate: Certificate,
    key: KeyPair,
}

impl Authority {
    pub fn new() -> Self {
        let mut parameters = CertificateParams::new(Vec::<String>::new()).unwrap();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters.not_before = date_time_ymd(2000, 1, 1);
        parameters.not_after = date_time_ymd(2040, 1, 1);
        parameters.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        parameters.distinguished_name = DistinguishedName::new();
        parameters
            .distinguished_name
            .push(DnType::CommonName, "SCAP ephemeral contract CA");
        let key = KeyPair::generate().unwrap();
        let certificate = parameters.self_signed(&key).unwrap();
        Self { certificate, key }
    }

    pub fn pem(&self) -> Vec<u8> {
        self.certificate.pem().into_bytes()
    }

    pub fn issue(&self, node: u64, expired: bool) -> Material {
        let endpoint = PeerEndpoint {
            uri: "https://127.0.0.1:1/".into(),
            cluster_id: CLUSTER,
            node_id: node,
        };
        let mut parameters = CertificateParams::new(vec![endpoint.server_name()]).unwrap();
        parameters.not_before = date_time_ymd(2000, 1, 1);
        parameters.not_after = date_time_ymd(if expired { 2001 } else { 2040 }, 1, 1);
        parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        parameters.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        parameters.distinguished_name = DistinguishedName::new();
        parameters
            .distinguished_name
            .push(DnType::CommonName, format!("SCAP test node {node}"));
        let key = KeyPair::generate().unwrap();
        let certificate = parameters
            .signed_by(&key, &self.certificate, &self.key)
            .unwrap();
        Material {
            certificate: certificate.pem().into_bytes(),
            key: key.serialize_pem().into_bytes(),
            der: certificate.der().as_ref().to_vec(),
        }
    }
}
