package net.cyberverso.sigillum.dssoracle;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/** Builds defective OCSP responses (RFC 6960) for the tests. */
final class OcspResponses {

    private OcspResponses() {
    }

    /**
     * Returns a well-formed, successful OCSP response from a throwaway
     * responder key, the same bytes on every call. It reports GOOD for serial number 1 of pki/ca-ecdsa,
     * which no certificate used by the tests has, so a validation that is
     * given it ignores it.
     */
    static byte[] wellFormed() throws Exception {
        X509CertificateHolder issuer = new X509CertificateHolder(
                Pem.decode(Files.readString(Path.of("..", "..", "testdata", "pki", "ca-ecdsa.pem"))));
        // A seeded SHA1PRNG makes the key and the signature, and so the response, the same on every run.
        java.security.SecureRandom random = java.security.SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(36);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), random);
        KeyPair responder = generator.generateKeyPair();
        DigestCalculatorProvider digests = new JcaDigestCalculatorProviderBuilder().build();
        CertificateID id = new CertificateID(digests.get(CertificateID.HASH_SHA1), issuer, BigInteger.ONE);
        Date thisUpdate = Date.from(Instant.parse("2030-01-14T10:00:00Z"));
        BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(
                new RespID(new X500Name("CN=sigillum test throwaway responder")));
        builder.addResponse(id, CertificateStatus.GOOD, thisUpdate, Date.from(Instant.parse("2030-01-21T10:00:00Z")));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").setSecureRandom(random)
                .build(responder.getPrivate());
        BasicOCSPResp basic = builder.build(signer, null, thisUpdate);
        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded();
    }

    /**
     * Returns an OCSP response that DSS uses: GOOD for pki/tsa, signed by
     * pki/ocsp-responder, which pki/ca-ecdsa delegated, with its certificate
     * included, and the same bytes on every call.
     */
    static byte[] forTsa() throws Exception {
        Path pki = Path.of("..", "..", "testdata", "pki");
        X509CertificateHolder issuer = new X509CertificateHolder(Pem.decode(Files.readString(pki.resolve("ca-ecdsa.pem"))));
        X509CertificateHolder tsa = new X509CertificateHolder(Pem.decode(Files.readString(pki.resolve("tsa.pem"))));
        X509CertificateHolder responder = new X509CertificateHolder(
                Pem.decode(Files.readString(pki.resolve("ocsp-responder.pem"))));
        java.security.PrivateKey key = java.security.KeyFactory.getInstance("EC").generatePrivate(
                new java.security.spec.PKCS8EncodedKeySpec(
                        Pem.decode(Files.readString(pki.resolve("keys/ocsp-responder.test-key.pem")))));
        java.security.SecureRandom random = java.security.SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(29);
        DigestCalculatorProvider digests = new JcaDigestCalculatorProviderBuilder().build();
        CertificateID id = new CertificateID(digests.get(CertificateID.HASH_SHA1), issuer, tsa.getSerialNumber());
        Date thisUpdate = Date.from(Instant.parse("2030-01-14T10:00:00Z"));
        BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(new RespID(responder.getSubject()));
        builder.addResponse(id, CertificateStatus.GOOD, thisUpdate, Date.from(Instant.parse("2030-01-21T10:00:00Z")));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").setSecureRandom(random).build(key);
        BasicOCSPResp basic = builder.build(signer, new X509CertificateHolder[] {responder}, thisUpdate);
        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded();
    }

    /**
     * Returns a response with its responseStatus, the first ENUMERATED of the
     * response, set to another value. The responseBytes are kept.
     */
    static byte[] withStatus(byte[] response, int status) {
        for (int i = 0; i + 2 < response.length; i++) {
            if (response[i] == 0x0a && response[i + 1] == 0x01) {
                byte[] copy = response.clone();
                copy[i + 2] = (byte) status;
                return copy;
            }
        }
        throw new IllegalStateException("responseStatus not found");
    }

    /**
     * Returns {@link #wellFormed()} with the producedAt time of its response
     * data replaced by "203001141000XXZ", of the same length, which is not a
     * time. producedAt is the first GeneralizedTime of the response.
     */
    static byte[] withMalformedProducedAt() throws Exception {
        byte[] response = wellFormed();
        byte[] time = "20300114100000Z".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] bad = "203001141000XXZ".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        for (int i = 0; i + time.length <= response.length; i++) {
            if (java.util.Arrays.equals(response, i, i + time.length, time, 0, time.length)) {
                System.arraycopy(bad, 0, response, i, bad.length);
                return response;
            }
        }
        throw new IllegalStateException("producedAt not found");
    }

    /**
     * Returns a successful OCSP response whose basic response is well formed
     * down to its list of responses, which holds one SingleResponse that is
     * only an INTEGER. The signature is not valid; it is never checked.
     */
    static byte[] malformedSingleResponse() throws IOException {
        DERSequence responseData = new DERSequence(new org.bouncycastle.asn1.ASN1Encodable[] {
            new DERTaggedObject(true, 2, new DEROctetString(new byte[20])),
            new DERGeneralizedTime("20300114100000Z"),
            new DERSequence(new DERSequence(new ASN1Integer(5)))});
        DERSequence basic = new DERSequence(new org.bouncycastle.asn1.ASN1Encodable[] {
            responseData,
            new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256),
            new DERBitString(new byte[8])});
        return new OCSPResponse(new OCSPResponseStatus(OCSPResponseStatus.SUCCESSFUL),
                new ResponseBytes(OCSPObjectIdentifiers.id_pkix_ocsp_basic, new DEROctetString(basic.getEncoded())))
                .getEncoded();
    }
}
