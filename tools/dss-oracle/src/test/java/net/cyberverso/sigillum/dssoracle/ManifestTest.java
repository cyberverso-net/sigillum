package net.cyberverso.sigillum.dssoracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The reader of testdata/manifest.toml that the tests use, and the divergences that it reads. */
class ManifestTest {

    private static final Path CORPUS = Path.of("..", "..", "testdata");

    private static final String HEADER = "# Manifest\n\n[header]\nformat-version = 2\n"
            + "validation-time = \"2030-01-15T10:00:00Z\"\n";

    private static final String ENTRY = "\n[[artefact]]\nid = \"pki/a\"\npath = \"pki/a.pem\"\nkind = \"certificate\"\n"
            + "expected-dss = { indication = \"INDETERMINATE\", sub-indication = \"OUT_OF_BOUNDS_NO_POE\" }\n";

    @TempDir
    Path temp;

    private Manifest read(String text) throws Exception {
        Files.writeString(temp.resolve("manifest.toml"), text);
        return Manifest.read(temp);
    }

    /**
     * The committed manifest records at least one divergence, the reader reads every
     * dss-divergence line of it, and each divergence is well formed. The divergences
     * themselves are listed in the manifest only.
     */
    @Test
    void theCommittedManifestNamesTheDivergencesOfDss() throws Exception {
        Manifest manifest = Manifest.read(CORPUS);
        String text = Files.readString(CORPUS.resolve("manifest.toml"));
        long lines = text.lines().filter(line -> line.startsWith("dss-divergence = ")).count();
        List<Manifest.Artefact> divergent = new ArrayList<>();
        for (String kind : new String[] {"certificate", "crl", "ocsp-response", "timestamp-token", "signed-document"}) {
            for (Manifest.Artefact artefact : manifest.ofKind(kind)) {
                if (artefact.divergence() != null) {
                    divergent.add(artefact);
                }
            }
        }
        assertFalse(divergent.isEmpty(), "the manifest records no divergence");
        assertEquals(lines, divergent.size());
        for (Manifest.Artefact artefact : divergent) {
            Manifest.Divergence divergence = artefact.divergence();
            assertTrue(divergence.entry().matches("DIV-[1-9][0-9]*"), artefact.id());
            assertTrue(divergence.result().matches("[A-Z-]+( [A-Z_]+)?"), artefact.id());
            assertNotEquals(artefact.expectedDss(), divergence.result(), artefact.id());
        }
    }

    @Test
    void aDivergenceIsReadWithAndWithoutItsSubIndication() throws Exception {
        Manifest manifest = read(HEADER + ENTRY
                + "dss-divergence = { entry = \"DIV-12\", indication = \"PASSED\" }\n"
                + ENTRY.replace("pki/a", "pki/b")
                + "dss-divergence = { entry = \"DIV-5\", indication = \"INDETERMINATE\","
                + " sub-indication = \"OUT_OF_BOUNDS_NOT_REVOKED\" }\n"
                + ENTRY.replace("pki/a", "pki/c"));
        assertEquals(new Manifest.Divergence("DIV-12", "PASSED"), manifest.get("pki/a").divergence());
        assertEquals(new Manifest.Divergence("DIV-5", "INDETERMINATE OUT_OF_BOUNDS_NOT_REVOKED"),
                manifest.get("pki/b").divergence());
        assertNull(manifest.get("pki/c").divergence());
    }

    @Test
    void aDivergenceThatCannotBeReadIsRefused() {
        for (String line : new String[] {
            "dss-divergence = { indication = \"PASSED\" }",
            "dss-divergence = { entry = \"DIV-x\", indication = \"PASSED\" }",
            "dss-divergence = { entry = \"DIV-5\", indication = \"PASSED\", colour = \"red\" }",
            "dss-divergence = \"DIV-5\"",
            "dss-divergence.entry = \"DIV-5\"",
            "dss-divergence.indication = \"PASSED\"",
            "\"dss-divergence\" = { entry = \"DIV-5\", indication = \"PASSED\" }",
            "dss-divergence= { entry = \"DIV-5\", indication = \"PASSED\" }",
            "[artefact.dss-divergence]"}) {
            assertThrows(IllegalArgumentException.class, () -> read(HEADER + ENTRY + line + "\n"), line);
        }
    }

    @Test
    void aHeaderOnTheFirstLineIsRead() throws Exception {
        Manifest manifest = read(HEADER.replace("# Manifest\n\n", "") + ENTRY);
        assertNull(manifest.get("pki/a").divergence());
    }

    @Test
    void anotherFormatVersionIsRefused() {
        for (String version : new String[] {"1", "3"}) {
            assertThrows(IllegalArgumentException.class,
                    () -> read(HEADER.replace("format-version = 2", "format-version = " + version) + ENTRY),
                    version);
        }
    }
}
