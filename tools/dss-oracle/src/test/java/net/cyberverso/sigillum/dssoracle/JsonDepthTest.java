package net.cyberverso.sigillum.dssoracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.management.ThreadMXBean;
import java.lang.management.ManagementFactory;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** Tests of the attribution of a refusal of the JSON schema validator of DSS to the document. */
class JsonDepthTest {

    /** The refusal that json-sKema 0.32.0 gives for JSON nested deeper than it accepts, on the stack of the worker. */
    private static RuntimeException refusal() throws InterruptedException {
        String deep = "[".repeat(JsonDepth.MAX_DEPTH + 1) + "]".repeat(JsonDepth.MAX_DEPTH + 1);
        RuntimeException[] refusal = new RuntimeException[1];
        Thread thread = new Thread(null, () -> {
            try {
                new com.github.erosb.jsonsKema.JsonParser(deep, URI.create("urn:test")).parse();
            } catch (RuntimeException e) {
                refusal[0] = e;
            }
        }, "json-skema", ResourceLimits.STACK_BYTES);
        thread.start();
        thread.join();
        if (refusal[0] == null) {
            throw new AssertionError("json-sKema accepted JSON nested deeper than " + JsonDepth.MAX_DEPTH);
        }
        return refusal[0];
    }

    @Test
    void theRefusalOfJsonSkemaIsRecognisedAsItIsOrAsACause() throws InterruptedException {
        RuntimeException refusal = refusal();
        assertTrue(refusal instanceof com.github.erosb.jsonsKema.TooDeeplyNestedValueException, refusal.toString());
        assertTrue(JsonDepth.isDepthLimitOfDss(refusal));
        assertTrue(JsonDepth.isDepthLimitOfDss(new IllegalStateException("wrapped", refusal)));
    }

    @Test
    void otherFailuresAreNotRecognised() {
        assertFalse(JsonDepth.isDepthLimitOfDss(new IllegalArgumentException("too deeply nested")));
        assertFalse(JsonDepth.isDepthLimitOfDss(new StackOverflowError()));
        assertFalse(JsonDepth.isDepthLimitOfDss(new IllegalStateException("x", new NullPointerException())));
    }

    @Test
    void onlyAJwsIsADocumentWhoseJsonDssParses() {
        assertTrue(JsonDepth.isJws(" {\"payload\":\"e30\"}".getBytes(StandardCharsets.US_ASCII)));
        assertTrue(JsonDepth.isJws("eyJhbGciOiJFUzI1NiJ9.e30.AAAA\n".getBytes(StandardCharsets.US_ASCII)));
        assertFalse(JsonDepth.isJws("%PDF-1.7\n".getBytes(StandardCharsets.US_ASCII)));
        assertFalse(JsonDepth.isJws(new byte[] {0x30, (byte) 0x82, 0x01, 0x00}));
        assertFalse(JsonDepth.isJws(new byte[0]));
    }

    /** A general JWS: a valid entry, then one whose protected header is nested too deep, with the given member. */
    private static byte[] generalWithDeepEntry(String signatureMember) {
        String ok = Documents.base64url("{\"alg\":\"ES256\"}");
        String deep = Documents.base64url(Documents.nestedHeader(JsonDepth.MAX_DEPTH));
        return ("{\"payload\":\"e30\",\"signatures\":[{\"protected\":\"" + ok + "\",\"signature\":\"AAAA\"},"
                + "{\"protected\":\"" + deep + "\"" + signatureMember + "}]}").getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * Issue #72, comment case 13: DSS skips an entry of {@code signatures},
     * or the flattened JWS, whose member {@code signature} is absent, null
     * or a blank string, and never parses its headers. It reads the headers
     * of an entry whose signature is any other value.
     */
    @Test
    void theHeadersOfAnEntryThatDssSkipsAreNotChecked() {
        for (String skipped : new String[] {"", ",\"signature\":null", ",\"signature\":\"\"",
            ",\"signature\":\" \\t\""}) {
            assertEquals(Optional.empty(), JsonDepth.check(generalWithDeepEntry(skipped)), skipped);
        }
        for (String read : new String[] {",\"signature\":\"AAAA\"", ",\"signature\":0",
            ",\"signature\":{}", ",\"signature\":[]", ",\"signature\":false"}) {
            assertTrue(JsonDepth.check(generalWithDeepEntry(read)).isPresent(), read);
        }
        String deep = Documents.base64url(Documents.nestedHeader(JsonDepth.MAX_DEPTH));
        byte[] flattened = ("{\"payload\":\"e30\",\"protected\":\"" + deep + "\",\"signature\":\"\"}")
                .getBytes(StandardCharsets.US_ASCII);
        assertEquals(Optional.empty(), JsonDepth.check(flattened));
    }

    /**
     * Issue #72, comment case 14: a document nested millions of levels deep
     * is rejected without the walk keeping a record per level.
     */
    @Test
    void aVeryDeepDocumentIsRejectedWithoutMemoryInProportionToItsDepth() {
        int depth = 4_000_000;
        byte[] document = ("{\"a\":" + "[".repeat(depth)).getBytes(StandardCharsets.US_ASCII);
        ThreadMXBean threads = (ThreadMXBean) ManagementFactory.getThreadMXBean();
        long before = threads.getCurrentThreadAllocatedBytes();
        assertTrue(JsonDepth.check(document).isPresent());
        long allocated = threads.getCurrentThreadAllocatedBytes() - before;
        assertTrue(allocated < 16L * 1024 * 1024, "allocated " + allocated + " bytes");
    }
}
