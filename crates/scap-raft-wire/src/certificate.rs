use sha2::{Digest, Sha256};
use x509_parser::parse_x509_certificate;

use crate::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertificateIdentity {
    pub fingerprint: [u8; 32],
    pub not_before: i64,
    pub not_after: i64,
}

/// Extract identity only from a leaf already verified by the mTLS stack.
/// This parser does not verify a signature, trust chain, usage or DNS name.
pub fn certificate_identity(der: &[u8], max_bytes: usize) -> Result<CertificateIdentity, Error> {
    if der.is_empty() || der.len() > max_bytes {
        return Err(Error::Limit("certificate DER"));
    }
    let (remaining, certificate) =
        parse_x509_certificate(der).map_err(|_| Error::Malformed("certificate DER"))?;
    if !remaining.is_empty() {
        return Err(Error::Malformed("certificate DER trailing bytes"));
    }
    let validity = certificate.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();
    if not_before > not_after {
        return Err(Error::Malformed("certificate validity interval"));
    }
    Ok(CertificateIdentity {
        fingerprint: Sha256::digest(der).into(),
        not_before,
        not_after,
    })
}
