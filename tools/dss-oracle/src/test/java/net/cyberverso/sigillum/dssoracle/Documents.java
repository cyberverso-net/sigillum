package net.cyberverso.sigillum.dssoracle;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.AbstractSignatureParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

/**
 * Signs test documents with DSS and the keys of the test PKI, offline and at
 * the planned signing time of the corpus, until the corpus holds signed
 * documents. The signer is {@code pki/signer-p256}, with the chain of
 * {@code pki/ca-ecdsa}, unless a method names another. The ECDSA random
 * numbers come from a seeded SHA1PRNG, so that each document is the same on
 * every run.
 */
final class Documents {

    /** The planned signing time of the corpus. */
    static final Instant SIGNING_TIME = Instant.parse("2029-12-16T10:00:00Z");
    /** The content that the test documents sign. */
    static final byte[] CONTENT = "sigillum test content\n".getBytes(StandardCharsets.US_ASCII);

    private static final Path PKI = Path.of("..", "..", "testdata", "pki");

    private Documents() {
    }

    /** A CAdES baseline B signature, enveloping the content. */
    static byte[] cades() throws Exception {
        return cades(SignaturePackaging.ENVELOPING, null);
    }

    /** The time of the signature timestamp of {@link #cadesT()}, one minute after the signing time. */
    static final Instant TIMESTAMP_TIME = Instant.parse("2029-12-16T10:01:00Z");

    /**
     * A CAdES baseline T signature, enveloping the content, with a signature
     * timestamp issued by pki/tsa at {@link #TIMESTAMP_TIME}.
     */
    static byte[] cadesT() throws Exception {
        return cadesT(false);
    }

    /**
     * {@link #cadesT()} whose timestamp token also holds a certificate that
     * plays no part: pki/signer-p256 with a subject name that is not valid
     * UTF-8, which DSS cannot decode but does not use.
     */
    static byte[] cadesTWithAnUnusedMalformedCertificate() throws Exception {
        return cadesT(true);
    }

    private static byte[] cadesT(boolean unusedMalformedCertificate) throws Exception {
        CAdESSignatureParameters parameters = new CAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_T);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        CAdESService service = new CAdESService(new CommonCertificateVerifier(true));
        service.setTspSource((algorithm, digest) -> timestamp(algorithm, digest, unusedMalformedCertificate));
        return sign(service, parameters, new InMemoryDocument(CONTENT, "content.txt"));
    }

    /**
     * Issues an RFC 3161 timestamp token (RFC 3161, section 2.4.2) with the
     * key of pki/tsa, at {@link #TIMESTAMP_TIME}, under the policy of the
     * test timestamping authority, with the certificate of pki/tsa and a
     * signingTime attribute at the same time.
     */
    private static eu.europa.esig.dss.model.TimestampBinary timestamp(DigestAlgorithm algorithm, byte[] digest,
            boolean unusedMalformedCertificate) {
        try {
            PrivateKey key = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(
                    Pem.decode(Files.readString(PKI.resolve("keys").resolve("tsa.test-key.pem")))));
            java.security.cert.X509Certificate tsa = DSSUtils.loadCertificate(
                    Files.readAllBytes(PKI.resolve("tsa.pem"))).getCertificate();
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(38);
            org.bouncycastle.operator.ContentSigner signer =
                    new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA")
                            .setSecureRandom(random).build(key);
            // A fixed signingTime attribute, so that Bouncy Castle does not add one from the clock.
            org.bouncycastle.asn1.cms.AttributeTable fixed = new org.bouncycastle.asn1.cms.AttributeTable(
                    new org.bouncycastle.asn1.cms.Attribute(org.bouncycastle.asn1.cms.CMSAttributes.signingTime,
                            new org.bouncycastle.asn1.DERSet(new org.bouncycastle.asn1.cms.Time(
                                    Date.from(TIMESTAMP_TIME)))));
            org.bouncycastle.cms.SignerInfoGenerator info =
                    new org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder(
                            new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder().build())
                            .setSignedAttributeGenerator(
                                    new org.bouncycastle.cms.DefaultSignedAttributeTableGenerator(fixed))
                            .build(signer, tsa);
            org.bouncycastle.tsp.TimeStampTokenGenerator generator = new org.bouncycastle.tsp.TimeStampTokenGenerator(
                    info, new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder().build()
                            .get(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                                    org.bouncycastle.asn1.oiw.OIWObjectIdentifiers.idSHA1)),
                    new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.3.6.1.4.1.32473.1.2"));
            List<org.bouncycastle.cert.X509CertificateHolder> holders = new ArrayList<>(List.of(
                    new org.bouncycastle.cert.X509CertificateHolder(tsa.getEncoded())));
            if (unusedMalformedCertificate) {
                holders.add(new org.bouncycastle.cert.X509CertificateHolder(Tokens.certificateWithInvalidUtf8Subject(
                        Files.readString(PKI.resolve("signer-p256.pem")))));
            }
            generator.addCertificates(new org.bouncycastle.util.CollectionStore<>(holders));
            org.bouncycastle.tsp.TimeStampRequestGenerator requests =
                    new org.bouncycastle.tsp.TimeStampRequestGenerator();
            requests.setCertReq(true);
            org.bouncycastle.tsp.TimeStampRequest request = requests.generate(
                    new org.bouncycastle.asn1.ASN1ObjectIdentifier(algorithm.getOid()), digest);
            return new eu.europa.esig.dss.model.TimestampBinary(generator.generate(request,
                    java.math.BigInteger.ONE, Date.from(TIMESTAMP_TIME)).getEncoded());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A CAdES baseline B signature of the content, detached from it. */
    static byte[] cadesDetached() throws Exception {
        return cades(SignaturePackaging.DETACHED, null);
    }

    /**
     * A CAdES baseline B signature, enveloping the content, with an explicit
     * signature policy identifier whose qualifier names a URL, from which a
     * validator configured to retrieve policy documents would fetch it.
     */
    static byte[] cadesWithPolicyUrl(String url) throws Exception {
        Policy policy = new Policy();
        policy.setId("1.3.6.1.4.1.32473.1.99");
        policy.setDigestAlgorithm(DigestAlgorithm.SHA256);
        policy.setDigestValue(new byte[32]);
        policy.setSpuri(url);
        return cades(SignaturePackaging.ENVELOPING, policy);
    }

    private static byte[] cades(SignaturePackaging packaging, Policy policy) throws Exception {
        CAdESSignatureParameters parameters = new CAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        parameters.setSignaturePackaging(packaging);
        if (policy != null) {
            parameters.bLevel().setSignaturePolicy(policy);
        }
        return sign(new CAdESService(new CommonCertificateVerifier(true)), parameters,
                new InMemoryDocument(CONTENT, "content.txt"));
    }

    /** A PAdES baseline B signature of {@link #pdf()}. */
    static byte[] pades() throws Exception {
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        parameters.setSigningTimeZone(TimeZone.getTimeZone("UTC"));
        return sign(new PAdESService(new CommonCertificateVerifier(true)), parameters,
                new InMemoryDocument(pdf(), "document.pdf"));
    }

    /** The signing time of the second signature of {@link #padesTwice()}, one hour after the first. */
    static final Instant SECOND_SIGNING_TIME = Instant.parse("2029-12-16T11:00:00Z");

    /**
     * {@link #pades()} signed a second time, in an incremental update, at
     * {@link #SECOND_SIGNING_TIME}: a PDF with two signatures, where DSS
     * compares the revision of the first with the final one.
     */
    static byte[] padesTwice() throws Exception {
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        parameters.setSigningTimeZone(TimeZone.getTimeZone("UTC"));
        return sign(new PAdESService(new CommonCertificateVerifier(true)), parameters,
                new InMemoryDocument(pades(), "document.pdf"), SECOND_SIGNING_TIME);
    }

    /**
     * Appends to a PDF from {@link #pdf()}, signed or not, an incremental
     * update (ISO 32000-1:2008, clause 7.5.6) that replaces its page by one
     * with a media box of the given size, in default user space units.
     */
    static byte[] withPageSize(byte[] pdf, int size) throws IOException {
        String text = new String(pdf, StandardCharsets.ISO_8859_1);
        String tail = text.substring(text.lastIndexOf("startxref") + "startxref".length()).strip();
        long previous = Long.parseLong(tail.substring(0, tail.indexOf('\n')).strip());
        int size2 = Integer.parseInt(text.substring(text.lastIndexOf("/Size ") + 6).split("[^0-9]")[0]);
        String page = "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 " + size + " " + size + "] >>\nendobj\n";
        int xref = pdf.length + page.length();
        String table = "xref\n3 1\n" + String.format("%010d 00000 n \n", pdf.length)
                + "trailer\n<< /Size " + size2 + " /Root 1 0 R /Prev " + previous + " >>\nstartxref\n" + xref
                + "\n%%EOF\n";
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(pdf);
        out.write((page + table).getBytes(StandardCharsets.ISO_8859_1));
        return out.toByteArray();
    }

    /**
     * Appends to a PDF from {@link #pdf()}, signed or not, an incremental
     * update that replaces its page by one showing a line of text in a
     * TrueType font that the PDF names but does not embed (ISO 32000-1:2008,
     * clause 9.6.3), so that a renderer substitutes a font of the host.
     */
    static byte[] withTextInAFontNotEmbedded(byte[] pdf) throws IOException {
        String text = new String(pdf, StandardCharsets.ISO_8859_1);
        String tail = text.substring(text.lastIndexOf("startxref") + "startxref".length()).strip();
        long previous = Long.parseLong(tail.substring(0, tail.indexOf('\n')).strip());
        int size = Integer.parseInt(text.substring(text.lastIndexOf("/Size ") + 6).split("[^0-9]")[0]);
        String content = "BT /F1 24 Tf 72 700 Td (sigillum) Tj ET";
        String page = "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents " + size
                + " 0 R /Resources << /Font << /F1 " + (size + 1) + " 0 R >> >> >>\nendobj\n";
        String stream = size + " 0 obj\n<< /Length " + content.length() + " >>\nstream\n" + content
                + "\nendstream\nendobj\n";
        String font = (size + 1) + " 0 obj\n<< /Type /Font /Subtype /TrueType /BaseFont /SigillumNoSuchFont"
                + " /Encoding /WinAnsiEncoding >>\nendobj\n";
        int pageAt = pdf.length;
        int streamAt = pageAt + page.length();
        int fontAt = streamAt + stream.length();
        int xref = fontAt + font.length();
        String table = "xref\n3 1\n" + String.format("%010d 00000 n \n", pageAt) + size + " 2\n"
                + String.format("%010d 00000 n \n%010d 00000 n \n", streamAt, fontAt)
                + "trailer\n<< /Size " + (size + 2) + " /Root 1 0 R /Prev " + previous + " >>\nstartxref\n" + xref
                + "\n%%EOF\n";
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(pdf);
        out.write((page + stream + font + table).getBytes(StandardCharsets.ISO_8859_1));
        return out.toByteArray();
    }

    /**
     * A JWS in the flattened JSON serialisation, not signed by any key,
     * whose protected header holds a member nested in the given number of
     * arrays: with the header object, the value is that number plus one
     * levels deep.
     */
    static byte[] jwsWithNestedHeader(int arrays) {
        String header = nestedHeader(arrays);
        return ("{\"payload\":\"e30\",\"protected\":\"" + base64url(header) + "\",\"signature\":\"AAAA\"}")
                .getBytes(StandardCharsets.US_ASCII);
    }

    /** The same header as {@link #jwsWithNestedHeader(int)}, in the compact serialisation. */
    static byte[] compactJwsWithNestedHeader(int arrays) {
        String header = nestedHeader(arrays);
        return (base64url(header) + ".e30.AAAA").getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * A JWS in the general JSON serialisation whose signatures member is
     * nested in the given number of arrays: with the root object, the
     * document is that number plus one levels deep.
     */
    static byte[] jwsWithNestedSignatures(int arrays) {
        return ("{\"payload\":\"e30\",\"signatures\":" + "[".repeat(arrays) + "]".repeat(arrays) + "}")
                .getBytes(StandardCharsets.US_ASCII);
    }

    /** A JWS header whose member {@code x} is nested in the given number of arrays. */
    static String nestedHeader(int arrays) {
        return "{\"alg\":\"ES256\",\"x\":" + "[".repeat(arrays) + "]".repeat(arrays) + "}";
    }

    /** A JWS in the general JSON serialisation with one signature whose protected header is the value given. */
    static byte[] generalJws(String protectedHeader) {
        return ("{\"payload\":\"e30\",\"signatures\":[{\"protected\":\"" + protectedHeader
                + "\",\"signature\":\"AAAA\"}]}").getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * {@link #jadesJson()} with an unprotected header holding one etsiU
     * component (ETSI TS 119 182-1 V1.2.1, clause 5.3.1): a JSON object whose
     * member is nested in the given number of arrays.
     */
    static byte[] jadesJsonWithNestedEtsiU(int arrays) throws Exception {
        String component = base64url("{\"sigTst\":" + "[".repeat(arrays) + "]".repeat(arrays) + "}");
        String json = new String(jadesJson(), StandardCharsets.US_ASCII);
        return ("{\"header\":{\"etsiU\":[\"" + component + "\"]}," + json.substring(json.indexOf('{') + 1))
                .getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * Crafted JWS documents of the review of #37, in the JSON serialisation
     * and not signed by any key, that carry JSON nested
     * {@link JsonDepth#MAX_DEPTH} levels deep, or about as deep, at places
     * that DSS parses or ignores: counter signatures (cSig, ETSI TS 119
     * 182-1 V1.2.1, clause 5.3.2) in etsiU components, encoded or clear, as a
     * string or an object, and chained; etsiU arrays with components that
     * DSS does not decode; members that the general syntax makes DSS ignore;
     * and encodings of the same values.
     *
     * @return the documents, by name
     */
    static java.util.Map<String, byte[]> craftedJws() {
        int n = JsonDepth.MAX_DEPTH;
        String ok = base64url("{\"alg\":\"ES256\"}");
        String deepHeader = base64url(nestedHeader(n));
        String compact = deepHeader + ".e30.AAAA";
        String flatDeep = "{\"payload\":\"e30\",\"protected\":\"" + deepHeader + "\",\"signature\":\"AAAA\"}";
        String component = base64url("{\"sigTst\":" + "[".repeat(n - 2) + "]".repeat(n - 2) + "}");
        java.util.Map<String, String> documents = new java.util.LinkedHashMap<>();
        documents.put("csig-compact-b64", flat(ok, "[\"" + base64url("{\"cSig\":\"" + compact + "\"}") + "\"]"));
        documents.put("csig-clear-obj", flat(ok, "[{\"cSig\":" + flatDeep + "}]"));
        documents.put("csig-clear-compact", flat(ok, "[{\"cSig\":\"" + compact + "\"}]"));
        String inner = flat(ok, "[\"" + base64url("{\"cSig\":\"" + compact + "\"}") + "\"]");
        documents.put("csig-nested", flat(ok, "[{\"cSig\":" + inner + "}]"));
        documents.put("csig-string-json", flat(ok, "[\"" + base64url("{\"cSig\":" + quoted(flatDeep) + "}") + "\"]"));
        documents.put("dup-protected", "{\"payload\":\"e30\",\"protected\":\"" + deepHeader
                + "\",\"protected\":\"" + ok + "\",\"signature\":\"AAAA\"}");
        documents.put("general-plus-top", "{\"payload\":\"e30\",\"protected\":\"" + deepHeader
                + "\",\"signatures\":[{\"protected\":\"" + ok + "\",\"signature\":\"AAAA\"}]}");
        documents.put("general-plus-top-header", "{\"payload\":\"e30\",\"header\":{\"etsiU\":[\"" + component
                + "\"]},\"signatures\":[{\"protected\":\"" + ok + "\",\"signature\":\"AAAA\"}]}");
        documents.put("escaped-slash", "{\"payload\":\"e30\",\"protected\":\"" + deepHeader.substring(0, 8)
                + "\\/" + deepHeader.substring(8) + "\",\"signature\":\"AAAA\"}");
        documents.put("surrogate", "{\"payload\":\"e30\",\"protected\":\"" + deepHeader.substring(0, 8)
                + "\\uD83D\\uDE00" + deepHeader.substring(8) + "\",\"signature\":\"AAAA\"}");
        documents.put("leading-space", " " + flatDeep);
        documents.put("etsiu-general", "{\"payload\":\"e30\",\"signatures\":[{\"protected\":\"" + ok
                + "\",\"header\":{\"etsiU\":[\"" + component + "\"]},\"signature\":\"AAAA\"}]}");
        documents.put("etsiu-lenient", flat(ok, "[\"" + component.substring(0, 4) + "*" + component.substring(4)
                + "\"]"));
        documents.put("etsiu-mixed", flat(ok, "[\"" + component + "\",{\"sigTst\":{}}]"));
        // DSS ignores a clear component with more than one member, and reads only the first member of an
        // encoded one, so a counter signature as a second member is not parsed.
        String second = "{\"unrecognized\":0,\"cSig\":\"" + compact + "\"}";
        documents.put("csig-second-member-clear", flat(ok, "[" + second + "]"));
        documents.put("csig-second-member-b64", flat(ok, "[\"" + base64url(second) + "\"]"));
        java.util.Map<String, byte[]> bytes = new java.util.LinkedHashMap<>();
        documents.forEach((name, text) -> bytes.put(name, text.getBytes(StandardCharsets.UTF_8)));
        return bytes;
    }

    /** A flattened JWS with the protected header and etsiU array given. */
    private static String flat(String protectedHeader, String etsiU) {
        return "{\"payload\":\"e30\",\"protected\":\"" + protectedHeader + "\",\"header\":{\"etsiU\":" + etsiU
                + "},\"signature\":\"AAAA\"}";
    }

    /** A JSON string of the text (RFC 8259, section 7). */
    private static String quoted(String text) {
        return "\"" + text.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    static String base64url(String text) {
        return java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(text.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * The default policy of DSS with the n-th empty {@code Cryptographic}
     * element, counted from 1 in document order, replaced by one whose
     * expiration dates have a date format that is not a pattern. In DSS
     * 6.5.1, 1 to 3 belong to signatures (signing certificate, CA
     * certificate, signature), 4 to 6 to counter-signatures, 7 to 9 to
     * timestamps, 10 to 12 to revocation data and 13 to evidence records.
     * With n = 0, the format of the global constraints is replaced instead.
     */
    static byte[] policyWithBadDateFormat(int n) throws IOException {
        String policy = new String(defaultPolicy(), StandardCharsets.UTF_8);
        if (n == 0) {
            return policy.replace("Format=\"yyyy-MM-dd\"", "Format=\"yyyy-MM-dq\"")
                    .getBytes(StandardCharsets.UTF_8);
        }
        int at = -1;
        for (int i = 0; i < n; i++) {
            at = policy.indexOf("<Cryptographic />", at + 1);
        }
        if (at < 0) {
            throw new IllegalArgumentException("the policy has fewer empty Cryptographic elements than " + n);
        }
        String bad = "<Cryptographic><AlgoExpirationDate Level=\"FAIL\" Format=\"yyyy-MM-dq\">"
                + "<Algo Date=\"2020-01-01\">SHA1</Algo></AlgoExpirationDate></Cryptographic>";
        return (policy.substring(0, at) + bad + policy.substring(at + "<Cryptographic />".length()))
                .getBytes(StandardCharsets.UTF_8);
    }

    /** A JAdES baseline B signature in the compact serialisation, enveloping the content. */
    static byte[] jades() throws Exception {
        return jades(JWSSerializationType.COMPACT_SERIALIZATION);
    }

    /** A JAdES baseline B signature in the flattened JSON serialisation, enveloping the content. */
    static byte[] jadesJson() throws Exception {
        return jades(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);
    }

    private static byte[] jades(JWSSerializationType serialisation) throws Exception {
        JAdESSignatureParameters parameters = new JAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        parameters.setJwsSerializationType(serialisation);
        return sign(new JAdESService(new CommonCertificateVerifier(true)), parameters,
                new InMemoryDocument(CONTENT, "content.txt"));
    }

    /**
     * A CAdES baseline B signature, enveloping the content, by
     * pki/signer-ed25519 with the chain of pki/ca-ed25519: Ed25519 (RFC 8032)
     * in CMS as RFC 8419 specifies it, which the default policy of DSS 6.5.1
     * does not accept and the aligned policy does (ADR-0023).
     */
    static byte[] cadesEd25519() throws Exception {
        CAdESSignatureParameters parameters = new CAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
        return sign(new CAdESService(new CommonCertificateVerifier(true)), parameters,
                new InMemoryDocument(CONTENT, "content.txt"), SIGNING_TIME, "signer-ed25519", "ca-ed25519");
    }

    private static <P extends AbstractSignatureParameters<?>> byte[] sign(DocumentSignatureService<P, ?> service,
            P parameters, DSSDocument content) throws Exception {
        return sign(service, parameters, content, SIGNING_TIME);
    }

    private static <P extends AbstractSignatureParameters<?>> byte[] sign(DocumentSignatureService<P, ?> service,
            P parameters, DSSDocument content, Instant signingTime) throws Exception {
        return sign(service, parameters, content, signingTime, "signer-p256", "ca-ecdsa");
    }

    private static <P extends AbstractSignatureParameters<?>> byte[] sign(DocumentSignatureService<P, ?> service,
            P parameters, DSSDocument content, Instant signingTime, String signerName, String caName)
            throws Exception {
        CertificateToken signer = DSSUtils.loadCertificate(Files.readAllBytes(PKI.resolve(signerName + ".pem")));
        CertificateToken ca = DSSUtils.loadCertificate(Files.readAllBytes(PKI.resolve(caName + ".pem")));
        boolean ed25519 = signerName.contains("ed25519");
        if (!ed25519) {
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        }
        parameters.setSigningCertificate(signer);
        parameters.setCertificateChain(List.of(signer, ca));
        parameters.bLevel().setSigningDate(Date.from(signingTime));
        ToBeSigned data = service.getDataToSign(content, parameters);
        PrivateKey key = KeyFactory.getInstance(ed25519 ? "Ed25519" : "EC").generatePrivate(
                new PKCS8EncodedKeySpec(Pem.decode(Files.readString(
                        PKI.resolve("keys").resolve(signerName + ".test-key.pem")))));
        Signature signature;
        if (ed25519) {
            // Ed25519 is deterministic (RFC 8032, section 5.1.6): no random numbers.
            signature = Signature.getInstance("Ed25519");
            signature.initSign(key);
        } else {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(37);
            signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(key, random);
        }
        signature.update(data.getBytes());
        DSSDocument signed = service.signDocument(content, parameters, new SignatureValue(
                ed25519 ? SignatureAlgorithm.ED25519 : SignatureAlgorithm.ECDSA_SHA256, signature.sign()));
        try (InputStream in = signed.openStream()) {
            return in.readAllBytes();
        }
    }

    /**
     * A PDF of one empty page, written out with its cross-reference table
     * (ISO 32000-1:2008, clause 7.5), so that the test needs no PDF library.
     */
    static byte[] pdf() throws IOException {
        List<String> objects = List.of(
                "<< /Type /Catalog /Pages 2 0 R >>",
                "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write("%PDF-1.7\n".getBytes(StandardCharsets.US_ASCII));
        List<Integer> offsets = new ArrayList<>();
        for (int i = 0; i < objects.size(); i++) {
            offsets.add(out.size());
            out.write(((i + 1) + " 0 obj\n" + objects.get(i) + "\nendobj\n").getBytes(StandardCharsets.US_ASCII));
        }
        int xref = out.size();
        StringBuilder table = new StringBuilder("xref\n0 " + (objects.size() + 1) + "\n0000000000 65535 f \n");
        for (int offset : offsets) {
            table.append(String.format("%010d 00000 n \n", offset));
        }
        table.append("trailer\n<< /Size ").append(objects.size() + 1).append(" /Root 1 0 R >>\nstartxref\n")
                .append(xref).append("\n%%EOF\n");
        out.write(table.toString().getBytes(StandardCharsets.US_ASCII));
        return out.toByteArray();
    }

    /** The default validation policy of DSS 6.5.1, as {@code dss-policy-jaxb} holds it. */
    static byte[] defaultPolicy() throws IOException {
        try (InputStream in = Documents.class.getResourceAsStream("/policy/constraint.xml")) {
            if (in == null) {
                throw new IOException("the default policy of DSS is not on the class path");
            }
            return in.readAllBytes();
        }
    }
}
