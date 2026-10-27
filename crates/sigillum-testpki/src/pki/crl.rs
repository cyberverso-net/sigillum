//! The CRLs of the test PKI (RFC 5280, section 5).
//!
//! ADR-0022: every CRL is assembled from the `x509-cert` CRL structures,
//! encoded with `der` and signed through [`KeyPair::sign`], the signer of
//! the certificates. Every CA that issues certificates, the root included,
//! has one current CRL. It lists the certificates of that CA whose
//! [`Revocation`] date is not after its `thisUpdate`, each with its reason
//! code. Three more CRLs of
//! `pki/ca-ecdsa` are defective: one expired, one signed with the wrong
//! key and one with the wrong issuer name.
//!
//! Every CRL is a version 2 CRL with the authority key identifier and CRL
//! number extensions (RFC 5280, sections 5.1.2.1, 5.2.1 and 5.2.3). Every
//! time is an offset from the fixed validation time of the manifest. The
//! files are DER-encoded, because the CRL distribution points of the
//! certificates are HTTP URIs (RFC 5280, section 4.2.1.13), and are named
//! after those URIs: `http://example.invalid/crl/<issuer>.crl` names
//! `crl/<issuer>.crl`.
//!
//! [`Revocation`]: super::hierarchy::Revocation

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use const_oid::db::rfc5280;
use der::DateTime;
use der::asn1::{BitString, GeneralizedTime, Uint, UtcTime};
use time::OffsetDateTime;
use x509_cert::Version;
use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
use x509_cert::ext::pkix::AuthorityKeyIdentifier;
use x509_cert::ext::pkix::crl::CrlNumber;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Time;

use super::hierarchy::{self, CERTIFICATES, CertSpec, ExpectedDss, Offset};
use super::issue;
use super::keys::{KeyPair, SignatureAlgorithm, to_der};
use super::{GenerateError, GeneratedFile, PkiError, Summary, certificate_id, sha256_hex};
use crate::manifest::{Artefact, DssResult, Indication, Kind, Links, Manifest, OpensslResult};
use SignatureAlgorithm as Sig;

/// The directory of the CRLs, relative to the manifest.
pub const DIRECTORY: &str = "crl";

/// `thisUpdate` of the current CRLs: one day before the validation time.
pub const THIS_UPDATE: Offset = Offset::days(-1);

/// `nextUpdate` of the current CRLs: six days after the validation time,
/// so that a CRL is issued every seven days.
pub const NEXT_UPDATE: Offset = Offset::days(6);

/// The common name in the issuer field of `crl/ca-ecdsa-wrong-issuer`. No
/// certificate of the test PKI has it in its subject.
pub const UNKNOWN_ISSUER: &str = "sigillum test unknown CA";

/// id-ce-expiredCertsOnCRL (ITU-T X.509 (10/2019), clause 9.5.2.8), which
/// RFC 5280 does not define.
pub const ID_CE_EXPIRED_CERTS_ON_CRL: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("2.5.29.60");

/// A defect built into a CRL on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Defect {
    /// The CRL is signed with the key of this certificate of the test PKI
    /// instead of the key of its issuer.
    WrongKey(&'static str),
    /// The issuer field holds this common name instead of the issuer's.
    WrongIssuerName(&'static str),
}

/// The specification of one CRL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrlSpec {
    /// The name of the CRL, used in its path and identifier.
    pub name: &'static str,
    /// The name of the CA certificate whose CRL this is.
    pub issuer: &'static str,
    /// The algorithm the CRL is signed with.
    pub algorithm: SignatureAlgorithm,
    /// `thisUpdate`, from the validation time.
    pub this_update: Offset,
    /// `nextUpdate`, from the validation time.
    pub next_update: Offset,
    /// The CRL number (RFC 5280, section 5.2.3).
    pub number: u8,
    /// The defect built into the CRL, if any.
    pub defect: Option<Defect>,
    /// The date of the extension expiredCertsOnCRL (ITU-T X.509 (10/2019),
    /// clause 9.5.2.8), from the validation time, or `None` without it.
    pub expired_certs_on_crl: Option<Offset>,
    /// The name of the covered certificate: a certificate of the issuer,
    /// not revoked, whose validation with this CRL gives the expected DSS
    /// result. The manifest notes name it first.
    pub covered: &'static str,
    /// Why the CRL exists, for the manifest.
    pub purpose: &'static str,
    /// The result expected from OpenSSL.
    pub expected_openssl: OpensslResult,
    /// The result expected from DSS: the X.509 certificate validation of
    /// ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, of the covered
    /// certificate, with this CRL as its revocation data.
    pub expected_dss: ExpectedDss,
    /// Remarks for the manifest, after the covered certificate.
    pub notes: Option<&'static str>,
}

/// The covered certificate passes (ETSI EN 319 102-1 V1.4.1, clause
/// 5.2.6.4, step 9).
const PASSED: ExpectedDss = ExpectedDss {
    indication: Indication::Passed,
    sub_indication: None,
};

/// The path validation of the covered certificate fails for another
/// reason than its revocation (ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4,
/// step 4 e)): a defect of its CA, or a CRL that cannot show that it is
/// not revoked.
const CHAIN_FAILURE: ExpectedDss = ExpectedDss {
    indication: Indication::Indeterminate,
    sub_indication: Some("CERTIFICATE_CHAIN_GENERAL_FAILURE"),
};

/// The issuer of the revocation data of the covered certificate has
/// expired at the validation time (ETSI EN 319 102-1 V1.4.1, clause
/// 5.2.6.4, step 8, which NOTE 6 defers from step 4).
const REVOCATION_OUT_OF_BOUNDS: ExpectedDss = ExpectedDss {
    indication: Indication::Indeterminate,
    sub_indication: Some("REVOCATION_OUT_OF_BOUNDS_NO_POE"),
};

/// The covered certificate has expired and is known not to have been
/// revoked (ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, step 7).
const OUT_OF_BOUNDS_NOT_REVOKED: ExpectedDss = ExpectedDss {
    indication: Indication::Indeterminate,
    sub_indication: Some("OUT_OF_BOUNDS_NOT_REVOKED"),
};

/// The revocation data of the covered certificate is usable but not fresh
/// (ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, step 4 a)).
const TRY_LATER: ExpectedDss = ExpectedDss {
    indication: Indication::Indeterminate,
    sub_indication: Some("TRY_LATER"),
};

/// The current CRL of `issuer`, valid at the validation time, checked with
/// the certificate `covered`.
const fn current(
    issuer: &'static str,
    algorithm: SignatureAlgorithm,
    covered: &'static str,
    purpose: &'static str,
) -> CrlSpec {
    CrlSpec {
        name: issuer,
        issuer,
        algorithm,
        this_update: THIS_UPDATE,
        next_update: NEXT_UPDATE,
        number: 2,
        defect: None,
        expired_certs_on_crl: None,
        covered,
        purpose,
        expected_openssl: OpensslResult::Verified,
        expected_dss: PASSED,
        notes: None,
    }
}

/// Every CRL of the test PKI: the current CRL of each CA that issues
/// certificates, then the defective CRLs of `pki/ca-ecdsa`.
pub const CRLS: [CrlSpec; 13] = [
    current(
        "root-ca",
        Sig::RsaPkcs1Sha256,
        "ca-ecdsa",
        "Current CRL of the root CA, which revokes none of the CA certificates it issued.",
    ),
    current(
        "ca-rsa",
        Sig::RsaPkcs1Sha256,
        "signer-rsa-2048",
        "Current CRL of the RSA PKCS#1 v1.5 CA, which revokes pki/signer-rsa-revoked.",
    ),
    current(
        "ca-rsa-pss",
        Sig::RsaPssSha256,
        "signer-rsa-pss-sha256",
        "Current CRL of the RSASSA-PSS CA, signed with RSASSA-PSS, which revokes pki/signer-rsa-pss-revoked.",
    ),
    current(
        "ca-ecdsa",
        Sig::EcdsaSha384,
        "signer-p256",
        "Current CRL of the ECDSA CA, which revokes pki/signer-p256-revoked and pki/signer-p256-revoked-after-signing.",
    ),
    current(
        "ca-ecdsa-p521",
        Sig::EcdsaSha512,
        "signer-p521",
        "Current CRL of the ECDSA P-521 CA, signed with ECDSA on P-521 and SHA-512, which revokes no certificate.",
    ),
    current(
        "ca-ed25519",
        Sig::Ed25519,
        "signer-ed25519",
        "Current CRL of the Ed25519 CA, which revokes pki/signer-ed25519-revoked.",
    ),
    CrlSpec {
        expected_dss: REVOCATION_OUT_OF_BOUNDS,
        notes: Some(
            "Issued one day before the validation time, at the instant the CA expires, so within its validity, because notAfter is inclusive (RFC 5280, section 4.1.2.5). ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4: step 4 does not check the validity of the issuer of the revocation data at the validation time, which NOTE 6 defers to step 8, and step 8 gives REVOCATION_OUT_OF_BOUNDS_NO_POE because the CA has expired.",
        ),
        ..current(
            "ca-expired",
            Sig::EcdsaSha256,
            "signer-under-expired-ca",
            "Current CRL of the expired intermediate CA, which revokes no certificate.",
        )
    },
    CrlSpec {
        expected_dss: CHAIN_FAILURE,
        notes: Some(
            "The covered certificate fails because its issuer is not a CA, not for want of revocation data.",
        ),
        ..current(
            "ca-without-ca-flag",
            Sig::EcdsaSha256,
            "signer-under-ca-without-ca-flag",
            "Current CRL of the CA certificate whose basic constraints do not assert cA, which revokes no certificate.",
        )
    },
    CrlSpec {
        expected_dss: CHAIN_FAILURE,
        notes: Some(
            "The covered certificate fails because its issuer has no basic constraints, not for want of revocation data.",
        ),
        ..current(
            "ca-without-basic-constraints",
            Sig::EcdsaSha256,
            "signer-under-ca-without-basic-constraints",
            "Current CRL of the CA certificate without basic constraints, which revokes no certificate.",
        )
    },
    CrlSpec {
        name: "ca-ecdsa-expired",
        this_update: Offset::days(-14),
        next_update: Offset::days(-7),
        number: 1,
        expected_openssl: OpensslResult::Rejected,
        // ETSI EN 319 102-1 V1.4.1, clause 5.2.5.4: the maximum accepted
        // freshness is the interval from thisUpdate to nextUpdate, seven
        // days, and the CRL was issued 14 days before the validation time,
        // so the freshness checker fails and step 4 a) of clause 5.2.6.4
        // gives TRY_LATER.
        expected_dss: TRY_LATER,
        notes: Some(
            "An earlier CRL of pki/ca-ecdsa, issued 14 days before the validation time. It lists pki/signer-p256-revoked, revoked before it was issued, and not pki/signer-p256-revoked-after-signing.",
        ),
        ..current(
            "ca-ecdsa",
            Sig::EcdsaSha384,
            "signer-p256",
            "CRL of the ECDSA CA whose nextUpdate is seven days before the validation time.",
        )
    },
    CrlSpec {
        name: "ca-ecdsa-wrong-key",
        defect: Some(Defect::WrongKey("signer-p384")),
        expected_openssl: OpensslResult::Rejected,
        // The signature does not verify with the issuer's key, so the CRL
        // cannot be used (RFC 5280, section 6.3.3, step (g)). The path
        // validation cannot then show that the certificate is not revoked
        // (RFC 5280, section 6.1.3, step (a)(3)) and fails, which step 4 e)
        // of clause 5.2.6.4 of ETSI EN 319 102-1 V1.4.1 reports.
        expected_dss: CHAIN_FAILURE,
        notes: Some(
            "Signed with the P-384 key of pki/signer-p384. The issuer name and the authority key identifier are those of pki/ca-ecdsa. DSS 6.5.1 gives this result.",
        ),
        ..current(
            "ca-ecdsa",
            Sig::EcdsaSha384,
            "signer-p256",
            "CRL of the ECDSA CA signed with another key than the CA's.",
        )
    },
    CrlSpec {
        name: "ca-ecdsa-wrong-issuer",
        defect: Some(Defect::WrongIssuerName(UNKNOWN_ISSUER)),
        expected_openssl: OpensslResult::Rejected,
        // The issuer name does not match the issuer of the covered
        // certificate, so the CRL does not apply to it (RFC 5280, section
        // 6.3.3, step (b)). The path validation cannot then show that the
        // certificate is not revoked (RFC 5280, section 6.1.3, step
        // (a)(3)) and fails, which step 4 e) of clause 5.2.6.4 of ETSI
        // EN 319 102-1 V1.4.1 reports.
        expected_dss: CHAIN_FAILURE,
        notes: Some(
            "The issuer name is \"O=sigillum test PKI, CN=sigillum test unknown CA\", which no certificate has as subject. The CRL is signed with the key of pki/ca-ecdsa and carries its authority key identifier. DSS 6.5.1 gives this result.",
        ),
        ..current(
            "ca-ecdsa",
            Sig::EcdsaSha384,
            "signer-p256",
            "CRL of the ECDSA CA whose issuer name is not the CA's.",
        )
    },
    CrlSpec {
        name: "ca-ecdsa-expired-certs",
        this_update: Offset::days(0),
        next_update: Offset::days(7),
        number: 3,
        // ITU-T X.509 (10/2019), clause 9.5.2.8: the scope of the CRL
        // covers the certificates that expired on or after this date.
        expired_certs_on_crl: Some(Offset::years(-1)),
        // The CRL shows that pki/signer-expired, which expired before it
        // was issued but within its scope, was not revoked: step 7 of
        // clause 5.2.6.4 of ETSI EN 319 102-1 V1.4.1.
        expected_dss: OUT_OF_BOUNDS_NOT_REVOKED,
        notes: Some(
            "A later CRL of pki/ca-ecdsa, issued at the validation time, after pki/signer-expired expired, with the non-critical extension expiredCertsOnCRL (ITU-T X.509 (10/2019), clause 9.5.2.8; RFC 5280 does not define it) set one year before the validation time. Its scope covers the certificates that expired on or after that date, so it shows the status of pki/signer-expired after expiry: not revoked. ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, step 7 and NOTE 8, give OUT_OF_BOUNDS_NOT_REVOKED.",
        ),
        ..current(
            "ca-ecdsa",
            Sig::EcdsaSha384,
            "signer-expired",
            "CRL of the ECDSA CA issued after pki/signer-expired expired, with the extension expiredCertsOnCRL.",
        )
    },
];

/// The identifier of the CRL with this name.
pub fn crl_id(name: &str) -> String {
    format!("{DIRECTORY}/{name}")
}

/// The current CRL of the issuer of `spec`, which its manifest entry links
/// in `revocation`, or `None` when its issuer has no CRL. The current CRL
/// of a CA has the CA's name.
pub fn current_crl(spec: &CertSpec) -> Option<&'static CrlSpec> {
    let issuer = spec.issuer?;
    CRLS.iter().find(|crl| crl.name == issuer)
}

fn certificate(name: &str) -> Result<&'static CertSpec, PkiError> {
    hierarchy::find(name).ok_or_else(|| PkiError::UnknownIssuer(name.to_owned()))
}

/// Generates every CRL of [`CRLS`], in that order.
///
/// # Errors
///
/// Returns a [`PkiError`] if a key or CRL cannot be produced.
pub fn generate(validation_time: OffsetDateTime) -> Result<Vec<GeneratedFile>, PkiError> {
    let mut keys: HashMap<&str, KeyPair> = HashMap::new();
    let mut files = Vec::with_capacity(CRLS.len());
    for spec in &CRLS {
        let signer = match spec.defect {
            Some(Defect::WrongKey(name)) => name,
            _ => spec.issuer,
        };
        for name in [spec.issuer, signer] {
            if !keys.contains_key(name) {
                let owner = certificate(name)?;
                keys.insert(owner.name, KeyPair::derive(owner.key, owner.name)?);
            }
        }
        let missing = || PkiError::UnknownIssuer(spec.issuer.to_owned());
        let issuer_key = keys.get(spec.issuer).ok_or_else(missing)?;
        let signing_key = keys.get(signer).ok_or_else(missing)?;
        let der = build(spec, issuer_key, signing_key, validation_time)?;
        files.push(crl_file(spec, der)?);
    }
    Ok(files)
}

/// Builds and signs one CRL (RFC 5280, section 5.1).
///
/// `issuer_key` is the key of the CA named by `spec.issuer`, which gives the
/// authority key identifier, and `signing_key` the key that signs.
///
/// # Errors
///
/// Returns a [`PkiError`] if a time is out of range, a value cannot be
/// encoded, or `signing_key` cannot sign with the algorithm of `spec`.
pub fn build(
    spec: &CrlSpec,
    issuer_key: &KeyPair,
    signing_key: &KeyPair,
    validation_time: OffsetDateTime,
) -> Result<Vec<u8>, PkiError> {
    let issuer = certificate(spec.issuer)?;
    let this_update = spec.this_update.from(validation_time)?;
    let next_update = spec.next_update.from(validation_time)?;
    // RFC 5280, section 5.1.2.3: the issuer name, encoded as the subject of
    // the issuer's certificate.
    let issuer_name = match spec.defect {
        Some(Defect::WrongIssuerName(common_name)) => issue::name(common_name)?,
        _ => issue::name(issuer.common_name)?,
    };
    let revoked = revoked_certificates(spec.issuer, this_update, validation_time)?;
    // RFC 5280, section 5.2.1: the authority key identifier, the key
    // identifier of the issuer, as in the certificates it issues; and
    // section 5.2.3: the CRL number. Both are non-critical.
    let mut extensions = vec![
        issue::extension(
            rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER,
            false,
            &AuthorityKeyIdentifier {
                key_identifier: Some(issue::key_identifier(&issue::spki_of(issuer_key)?)?),
                authority_cert_issuer: None,
                authority_cert_serial_number: None,
            },
        )?,
        issue::extension(
            rfc5280::ID_CE_CRL_NUMBER,
            false,
            &CrlNumber(Uint::new(&[spec.number]).map_err(|_| PkiError::Encoding)?),
        )?,
    ];
    if let Some(since) = spec.expired_certs_on_crl {
        // ITU-T X.509 (10/2019), clause 9.5.2.8: always non-critical; the
        // value is a GeneralizedTime.
        extensions.push(issue::extension(
            ID_CE_EXPIRED_CERTS_ON_CRL,
            false,
            &generalized_time(since.from(validation_time)?)?,
        )?);
    }
    // RFC 5280, section 5.1.1.2: signatureAlgorithm repeats the signature
    // field of the TBSCertList.
    let algorithm = spec.algorithm.identifier()?;
    let tbs_cert_list = TbsCertList {
        // RFC 5280, section 5.1.2.1: version 2, because extensions are present.
        version: Version::V2,
        signature: algorithm.clone(),
        issuer: issuer_name,
        this_update: time(this_update)?,
        next_update: Some(time(next_update)?),
        // RFC 5280, section 5.1.2.6: the list is absent when it is empty.
        revoked_certificates: (!revoked.is_empty()).then_some(revoked),
        crl_extensions: Some(extensions),
    };
    let signature = signing_key.sign(spec.algorithm, &to_der(&tbs_cert_list)?)?;
    to_der(&CertificateList {
        tbs_cert_list,
        signature_algorithm: algorithm,
        signature: BitString::from_bytes(&signature).map_err(|_| PkiError::Encoding)?,
    })
}

/// The certificates issued by `issuer` that are revoked on or before
/// `this_update`, by serial number, each with its revocation date and its
/// reason code entry extension (RFC 5280, sections 5.1.2.6 and 5.3.1).
fn revoked_certificates(
    issuer: &str,
    this_update: OffsetDateTime,
    validation_time: OffsetDateTime,
) -> Result<Vec<RevokedCert>, PkiError> {
    let mut revoked = Vec::new();
    for spec in CERTIFICATES.iter().filter(|s| s.issuer == Some(issuer)) {
        let Some(revocation) = spec.revocation else {
            continue;
        };
        let date = revocation.date.from(validation_time)?;
        if date > this_update {
            continue;
        }
        revoked.push((
            spec.serial,
            RevokedCert {
                serial_number: SerialNumber::new(&issue::serial_bytes(spec.serial))
                    .map_err(|_| PkiError::Encoding)?,
                revocation_date: time(date)?,
                crl_entry_extensions: Some(vec![issue::extension(
                    rfc5280::ID_CE_CRL_REASONS,
                    false,
                    &revocation.reason,
                )?]),
            },
        ));
    }
    revoked.sort_by_key(|(serial, _)| *serial);
    Ok(revoked.into_iter().map(|(_, entry)| entry).collect())
}

/// A GeneralizedTime at `at`, to the second.
fn generalized_time(at: OffsetDateTime) -> Result<GeneralizedTime, PkiError> {
    let seconds = u64::try_from(at.unix_timestamp()).map_err(|_| PkiError::Time)?;
    let date_time = DateTime::from_unix_duration(std::time::Duration::from_secs(seconds))
        .map_err(|_| PkiError::Time)?;
    Ok(GeneralizedTime::from_date_time(date_time))
}

/// A CRL time: UTCTime through 2049 and GeneralizedTime from 2050 (RFC 5280,
/// sections 5.1.2.4, 5.1.2.5 and 5.1.2.6).
pub fn time(at: OffsetDateTime) -> Result<Time, PkiError> {
    let seconds = u64::try_from(at.unix_timestamp()).map_err(|_| PkiError::Time)?;
    let date_time = DateTime::from_unix_duration(std::time::Duration::from_secs(seconds))
        .map_err(|_| PkiError::Time)?;
    if date_time.year() <= UtcTime::MAX_YEAR {
        UtcTime::from_date_time(date_time)
            .map(Time::UtcTime)
            .map_err(|_| PkiError::Time)
    } else {
        Ok(Time::GeneralTime(GeneralizedTime::from_date_time(
            date_time,
        )))
    }
}

fn crl_file(spec: &CrlSpec, der: Vec<u8>) -> Result<GeneratedFile, PkiError> {
    let issuer = certificate(spec.issuer)?;
    let mut chain = vec![certificate_id(issuer.name)];
    chain.extend(
        hierarchy::chain(issuer)?
            .iter()
            .map(|above| certificate_id(above.name)),
    );
    let artefact = Artefact {
        id: crl_id(spec.name),
        path: PathBuf::from(format!("{DIRECTORY}/{}.crl", spec.name)),
        sha256: sha256_hex(&der),
        kind: Kind::Crl,
        purpose: spec.purpose.to_owned(),
        expected_openssl: spec.expected_openssl,
        expected_dss: DssResult::Indication {
            indication: spec.expected_dss.indication,
            sub_indication: spec.expected_dss.sub_indication.map(str::to_owned),
        },
        links: Links {
            issuer: chain.first().cloned(),
            chain,
            revocation: Vec::new(),
            content: None,
            timestamp_chain: Vec::new(),
        },
        dss_divergence: None,
        notes: Some(match spec.notes {
            Some(notes) => format!("{} {notes}", covered_note(spec)),
            None => covered_note(spec),
        }),
    };
    Ok(GeneratedFile {
        artefact,
        contents: der,
    })
}

/// The first sentence of the notes of a CRL entry, which names the
/// covered certificate.
fn covered_note(spec: &CrlSpec) -> String {
    format!("Covered certificate: {}.", certificate_id(spec.covered))
}

/// Reports whether an entry belongs to what `generate crls` produces: a CRL
/// whose identifier is under [`DIRECTORY`].
fn generated_here(artefact: &Artefact) -> bool {
    artefact.kind == Kind::Crl && artefact.id.starts_with(&format!("{DIRECTORY}/"))
}

/// Generates the CRLs with the validation time of the manifest at
/// `manifest_path`, writes each file under the manifest's directory, and
/// records each in the manifest, as [`super::write_into_corpus`] does for
/// the certificates. The certificates must already be in the manifest.
///
/// The `revocation` links of the CRL entries it replaces are kept. CRL
/// entries under [`DIRECTORY`] that the generator no longer produces
/// are removed, with every `revocation` link to them; their files are not
/// deleted. In each certificate entry of the test PKI, the `revocation`
/// links to CRLs of this generator are replaced by a link to the current
/// CRL of its issuer, placed first, and other links are kept.
///
/// # Errors
///
/// Returns a [`GenerateError`] if the manifest cannot be read or updated,
/// for example because it lacks the certificates that the CRLs link, or a
/// file cannot be generated or written.
pub fn write_into_corpus(manifest_path: &Path) -> Result<Summary, GenerateError> {
    super::write_generated(
        manifest_path,
        DIRECTORY,
        generated_here,
        |manifest| generate(manifest.header.validation_time).map_err(GenerateError::Pki),
        link_certificates,
    )
}

/// Sets the `revocation` links of the certificate entries of the test PKI:
/// the links to `generated` CRLs are replaced by the current CRL of the
/// certificate's issuer, if it has one, in first place.
fn link_certificates(manifest: &mut Manifest, generated: &[String]) {
    for spec in &CERTIFICATES {
        let id = certificate_id(spec.name);
        let Some(entry) = manifest
            .artefacts
            .iter_mut()
            .find(|a| a.id == id && a.kind == Kind::Certificate)
        else {
            continue;
        };
        entry
            .links
            .revocation
            .retain(|link| !generated.contains(link));
        if let Some(crl) = current_crl(spec) {
            entry.links.revocation.insert(0, crl_id(crl.name));
        }
    }
}

#[cfg(test)]
mod tests;
