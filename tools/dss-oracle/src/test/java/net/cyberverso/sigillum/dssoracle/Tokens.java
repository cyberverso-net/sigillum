package net.cyberverso.sigillum.dssoracle;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

/** Derives defective timestamp tokens from the corpus for the tests. */
final class Tokens {

    /** An object identifier under the SHA-2 arc that names no algorithm. */
    static final String UNKNOWN_IMPRINT_OID = "2.16.840.1.101.3.4.2.127";

    private static final String POLICY = "1.3.6.1.4.1.32473.1.2";
    private static final String SHA256 = "2.16.840.1.101.3.4.2.1";

    private Tokens() {
    }

    /**
     * Replaces the algorithm of the message imprint of a token by
     * {@link #UNKNOWN_IMPRINT_OID}. The imprint follows the policy in the
     * TSTInfo, so the first SHA-256 identifier after the policy is replaced.
     * Both identifiers have the same length, so no length changes. The
     * signature no longer verifies, which does not matter for a token that
     * must be rejected before validation.
     */
    static byte[] withUnknownImprintAlgorithm(byte[] token) throws IOException {
        return withImprintAlgorithm(token, UNKNOWN_IMPRINT_OID);
    }

    /**
     * Replaces the algorithm of the message imprint of a token by another
     * identifier of the same encoded length, such as SHAKE-128
     * (2.16.840.1.101.3.4.2.11) or SHAKE-256 (2.16.840.1.101.3.4.2.12).
     */
    static byte[] withImprintAlgorithm(byte[] token, String oid) throws IOException {
        byte[] policy = new ASN1ObjectIdentifier(POLICY).getEncoded();
        byte[] sha256 = new ASN1ObjectIdentifier(SHA256).getEncoded();
        byte[] unknown = new ASN1ObjectIdentifier(oid).getEncoded();
        if (sha256.length != unknown.length) {
            throw new IllegalStateException("identifiers of different lengths");
        }
        int at = indexOf(token, sha256, indexOf(token, policy, 0));
        byte[] copy = token.clone();
        System.arraycopy(unknown, 0, copy, at, unknown.length);
        return copy;
    }

    /**
     * Replaces the SEQUENCE tag (0x30) that starts the ECDSA signature value
     * of a token, an ECDSA-Sig-Value (RFC 5754, section 3.3), by 0x01. The
     * CMS structure stays well formed; only the signature value cannot be
     * decoded.
     */
    static byte[] withMalformedSignature(byte[] token) throws Exception {
        byte[] signature = new CMSSignedData(token).getSignerInfos().getSigners().iterator().next().getSignature();
        int at = indexOf(token, signature, 0);
        if (token[at] != 0x30) {
            throw new IllegalStateException("the signature value is not a SEQUENCE");
        }
        byte[] copy = token.clone();
        copy[at] = 0x01;
        return copy;
    }

    /**
     * Returns a DER certificate of the test PKI with the first byte of the
     * value of its subject common name replaced by 0xD3, which starts a
     * two-byte UTF-8 sequence that the next character does not continue.
     */
    static byte[] certificateWithInvalidUtf8Subject(String pem) throws Exception {
        X509CertificateHolder holder = new X509CertificateHolder(Pem.decode(pem));
        String commonName = holder.getSubject().getRDNs(BCStyle.CN)[0]
                .getFirst().getValue().toString();
        byte[] der = holder.getEncoded();
        byte[] value = commonName.getBytes(StandardCharsets.UTF_8);
        int at = lastIndexOf(der, value);
        der[at] = (byte) 0xd3;
        return der;
    }

    private static int lastIndexOf(byte[] data, byte[] pattern) {
        for (int i = data.length - pattern.length; i >= 0; i--) {
            if (Arrays.equals(data, i, i + pattern.length, pattern, 0, pattern.length)) {
                return i;
            }
        }
        throw new IllegalStateException("pattern not found");
    }

    /**
     * Removes the encapsulated content (the TSTInfo) of a token and keeps its
     * content type, id-ct-TSTInfo, as a detached CMS structure would.
     */
    static byte[] withoutEncapsulatedContent(byte[] token) throws IOException {
        SignedData signedData = signedData(token);
        SignedData detached = new SignedData(signedData.getDigestAlgorithms(),
                new ContentInfo(signedData.getEncapContentInfo().getContentType(), null),
                signedData.getCertificates(), signedData.getCRLs(), signedData.getSignerInfos());
        return new ContentInfo(CMSObjectIdentifiers.signedData, detached).getEncoded("DER");
    }

    /**
     * Replaces the ESS signingCertificateV2 attribute of the signer by a
     * signingCertificate (version 1) attribute holding one ESSCertID with an
     * empty certificate hash.
     */
    static byte[] withEmptySigningCertificateHash(byte[] token) throws IOException {
        Attribute attribute = new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificate,
                new DERSet(new SigningCertificate(new ESSCertID(new byte[0]))));
        return withSigningCertificateAttribute(token, attribute);
    }

    /**
     * Replaces the hash algorithm of the ESSCertIDv2 of the signer by
     * SHAKE-128, which DSS knows but cannot compute; the hash value and the
     * issuer and serial number are kept.
     */
    static byte[] withShake128SigningCertificateHash(byte[] token) throws IOException {
        SignerInfo signer = SignerInfo.getInstance(signedData(token).getSignerInfos().getObjectAt(0));
        Attribute current = new AttributeTable(signer.getAuthenticatedAttributes())
                .get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);
        ESSCertIDv2 id = SigningCertificateV2.getInstance(current.getAttrValues().getObjectAt(0)).getCerts()[0];
        ESSCertIDv2 shake = new ESSCertIDv2(new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake128),
                id.getCertHash(), id.getIssuerSerial());
        Attribute attribute = new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2,
                new DERSet(new SigningCertificateV2(new ESSCertIDv2[] {shake})));
        return withSigningCertificateAttribute(token, attribute);
    }

    /**
     * Replaces the ESS signing certificate attributes of the signer by the
     * given ones and signs the token again with the key of pki/tsa, so that
     * the signature verifies. The ECDSA random numbers come from a seeded
     * SHA1PRNG.
     */
    static byte[] resignedWithSigningCertificates(byte[] token, Attribute... replacements) throws Exception {
        SignedData signedData = signedData(token);
        SignerInfo signer = SignerInfo.getInstance(signedData.getSignerInfos().getObjectAt(0));
        ASN1EncodableVector attributes = new ASN1EncodableVector();
        for (ASN1Encodable encodable : signer.getAuthenticatedAttributes()) {
            Attribute existing = Attribute.getInstance(encodable);
            if (!existing.getAttrType().equals(PKCSObjectIdentifiers.id_aa_signingCertificateV2)
                    && !existing.getAttrType().equals(PKCSObjectIdentifiers.id_aa_signingCertificate)) {
                attributes.add(existing);
            }
        }
        for (Attribute replacement : replacements) {
            attributes.add(replacement);
        }
        DERSet signed = new DERSet(attributes);
        PrivateKey key = KeyFactory.getInstance("EC").generatePrivate(
                new PKCS8EncodedKeySpec(Pem.decode(Files.readString(
                        Path.of("..", "..", "testdata", "pki", "keys", "tsa.test-key.pem")))));
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(36);
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(key, random);
        signature.update(signed.getEncoded("DER"));
        SignerInfo changed = new SignerInfo(signer.getSID(), signer.getDigestAlgorithm(), signed,
                signer.getDigestEncryptionAlgorithm(), new DEROctetString(signature.sign()),
                signer.getUnauthenticatedAttributes());
        SignedData result = new SignedData(signedData.getDigestAlgorithms(), signedData.getEncapContentInfo(),
                signedData.getCertificates(), signedData.getCRLs(), new DERSet(changed));
        return new ContentInfo(CMSObjectIdentifiers.signedData, result).getEncoded("DER");
    }

    /** Returns the ESSCertID (SHA-1) and ESSCertIDv2 (SHA-256) of pki/tsa, with its issuer and serial number. */
    static ESSCertID tsaCertId() throws Exception {
        X509CertificateHolder tsa = tsa();
        return new ESSCertID(MessageDigest.getInstance("SHA-1").digest(tsa.getEncoded()),
                issuerSerial(tsa));
    }

    static ESSCertIDv2 tsaCertIdV2() throws Exception {
        X509CertificateHolder tsa = tsa();
        return new ESSCertIDv2(MessageDigest.getInstance("SHA-256").digest(tsa.getEncoded()),
                issuerSerial(tsa));
    }

    static IssuerSerial tsaIssuerSerial() throws Exception {
        return issuerSerial(tsa());
    }

    private static X509CertificateHolder tsa() throws Exception {
        return new X509CertificateHolder(Pem.decode(Files.readString(
                Path.of("..", "..", "testdata", "pki", "tsa.pem"))));
    }

    private static IssuerSerial issuerSerial(X509CertificateHolder c) {
        return new IssuerSerial(
                new GeneralNames(new GeneralName(c.getIssuer())),
                c.getSerialNumber());
    }

    private static SignedData signedData(byte[] token) {
        return SignedData.getInstance(ContentInfo.getInstance(token).getContent());
    }

    /** Replaces the signing certificate attributes of the signer; the signature no longer verifies. */
    private static byte[] withSigningCertificateAttribute(byte[] token, Attribute attribute) throws IOException {
        SignedData signedData = signedData(token);
        SignerInfo signer = SignerInfo.getInstance(signedData.getSignerInfos().getObjectAt(0));
        ASN1EncodableVector attributes = new ASN1EncodableVector();
        for (ASN1Encodable encodable : signer.getAuthenticatedAttributes()) {
            Attribute existing = Attribute.getInstance(encodable);
            if (!existing.getAttrType().equals(PKCSObjectIdentifiers.id_aa_signingCertificateV2)
                    && !existing.getAttrType().equals(PKCSObjectIdentifiers.id_aa_signingCertificate)) {
                attributes.add(existing);
            }
        }
        attributes.add(attribute);
        SignerInfo changed = new SignerInfo(signer.getSID(), signer.getDigestAlgorithm(), new DERSet(attributes),
                signer.getDigestEncryptionAlgorithm(), signer.getEncryptedDigest(),
                signer.getUnauthenticatedAttributes());
        SignedData result = new SignedData(signedData.getDigestAlgorithms(), signedData.getEncapContentInfo(),
                signedData.getCertificates(), signedData.getCRLs(), new DERSet(changed));
        return new ContentInfo(CMSObjectIdentifiers.signedData, result).getEncoded("DER");
    }

    /** Removes the certificates of a token; the signer is then found among the supplied certificates. */
    static byte[] withoutCertificates(byte[] token) throws Exception {
        CMSSignedData cms = new CMSSignedData(token);
        Store<X509CertificateHolder> none =
                new CollectionStore<>(List.of());
        return CMSSignedData.replaceCertificatesAndCRLs(cms, none, null, null).getEncoded("DER");
    }

    /**
     * Moves the certificates of a token to the unsigned attribute
     * certificateValues of its signer (id-aa-ets-certValues, ETSI EN 319
     * 122-1 V1.3.1, clause A.1.1.2), with the given certificates in their
     * place, and leaves SignedData without certificates. The attribute is
     * unsigned, so the signature still verifies.
     */
    static byte[] withCertificateValues(byte[] token, byte[]... certificates) throws Exception {
        SignedData signedData = signedData(token);
        SignerInfo signer = SignerInfo.getInstance(signedData.getSignerInfos().getObjectAt(0));
        ASN1EncodableVector values = new ASN1EncodableVector();
        for (byte[] certificate : certificates) {
            values.add(Certificate.getInstance(certificate));
        }
        Attribute attribute = new Attribute(PKCSObjectIdentifiers.id_aa_ets_certValues,
                new DERSet(new DERSequence(values)));
        SignerInfo changed = new SignerInfo(signer.getSID(), signer.getDigestAlgorithm(),
                signer.getAuthenticatedAttributes(), signer.getDigestEncryptionAlgorithm(),
                signer.getEncryptedDigest(), new DERSet(attribute));
        SignedData result = new SignedData(signedData.getDigestAlgorithms(), signedData.getEncapContentInfo(),
                null, signedData.getCRLs(), new DERSet(changed));
        return new ContentInfo(CMSObjectIdentifiers.signedData, result).getEncoded("DER");
    }

    /**
     * Returns a token whose SignedData holds the given number of copies of
     * each of its certificates, in a SET that is not sorted. The
     * certificates are not signed, so the signature still verifies.
     */
    static byte[] withCopiesOfItsCertificates(byte[] token, int copies) {
        SignedData signedData = signedData(token);
        ASN1EncodableVector certificates = new ASN1EncodableVector();
        for (ASN1Encodable certificate : signedData.getCertificates()) {
            for (int i = 0; i < copies; i++) {
                certificates.add(certificate);
            }
        }
        SignedData result = new SignedData(signedData.getDigestAlgorithms(), signedData.getEncapContentInfo(),
                new DLSet(certificates), signedData.getCRLs(), signedData.getSignerInfos());
        try {
            return new ContentInfo(CMSObjectIdentifiers.signedData, result).getEncoded("DL");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Returns a token whose SignedData holds the given certificates, in
     * their order, in a SET that is not sorted. The certificates are not
     * signed, so the signature still verifies.
     */
    static byte[] withCertificates(byte[] token, byte[]... certificates) {
        SignedData signedData = signedData(token);
        ASN1EncodableVector vector = new ASN1EncodableVector();
        for (byte[] certificate : certificates) {
            vector.add(Certificate.getInstance(certificate));
        }
        SignedData result = new SignedData(signedData.getDigestAlgorithms(), signedData.getEncapContentInfo(),
                new DLSet(vector), signedData.getCRLs(), signedData.getSignerInfos());
        try {
            return new ContentInfo(CMSObjectIdentifiers.signedData, result).getEncoded("DL");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Returns pki/ca-ecdsa with the value of its basicConstraints extension
     * changed from a SEQUENCE to a SET. Bouncy Castle reads the certificate
     * structure, but the certificate factory, which decodes basicConstraints,
     * refuses it, so DSS cannot convert it to a certificate token.
     */
    static byte[] caEcdsaWithMalformedBasicConstraints() throws Exception {
        byte[] der = Pem.decode(Files.readString(
                Path.of("..", "..", "testdata", "pki", "ca-ecdsa.pem")));
        int oid = indexOf(der, new byte[] {0x06, 0x03, 0x55, 0x1d, 0x13}, 0);
        int octetString = indexOf(der, new byte[] {0x04}, oid + 5);
        der[octetString + 2] = 0x31;
        return der;
    }

    /**
     * Returns pki/ca-ecdsa with the keyIdentifier tag of its
     * authorityKeyIdentifier extension changed to an illegal one, 0x4A. The
     * certificate factory accepts it, but DSS cannot decode its extensions.
     */
    static byte[] caEcdsaWithMalformedAuthorityKeyIdentifier() throws Exception {
        byte[] der = Pem.decode(Files.readString(
                Path.of("..", "..", "testdata", "pki", "ca-ecdsa.pem")));
        int oid = indexOf(der, new byte[] {0x06, 0x03, 0x55, 0x1d, 0x23}, 0);
        int octetString = indexOf(der, new byte[] {0x04}, oid + 5);
        der[octetString + 4] = 0x4a;
        return der;
    }

    /**
     * Returns a certificate with the subject of pki/ca-ecdsa, issued under
     * the name of pki/root-ca, with a key of its own and the malformed
     * authorityKeyIdentifier of {@link #caEcdsaWithMalformedAuthorityKeyIdentifier}:
     * a certificate of the same name that did not issue pki/tsa.
     */
    static byte[] otherKeyWithTheSubjectOfCaEcdsa() throws Exception {
        X509CertificateHolder ca = new X509CertificateHolder(
                caEcdsaWithMalformedAuthorityKeyIdentifier());
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(72);
        generator.initialize(256, random);
        KeyPair pair = generator.generateKeyPair();
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                ca.getIssuer(), BigInteger.valueOf(0x7201), ca.getNotBefore(), ca.getNotAfter(),
                ca.getSubject(), SubjectPublicKeyInfo.getInstance(
                        pair.getPublic().getEncoded()));
        builder.addExtension(ca.getExtension(Extension.authorityKeyIdentifier));
        return builder.build(new JcaContentSignerBuilder("SHA256withECDSA")
                .build(pair.getPrivate())).getEncoded();
    }

    private static int indexOf(byte[] data, byte[] pattern, int from) {
        for (int i = Math.max(from, 0); i + pattern.length <= data.length; i++) {
            if (Arrays.equals(data, i, i + pattern.length, pattern, 0, pattern.length)) {
                return i;
            }
        }
        throw new IllegalStateException("pattern not found");
    }
}
