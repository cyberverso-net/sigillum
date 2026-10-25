package net.cyberverso.sigillum.dssoracle;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads the entries of {@code testdata/manifest.toml} that the tests need.
 * The manifest is written by {@code sigillum-testpki} with one key per line
 * and inline tables on one line, as {@code testdata/README.md} describes, so
 * a reader of that layout suffices. It is not a TOML parser.
 */
final class Manifest {

    /**
     * An artefact of the manifest.
     *
     * @param id the identifier, such as {@code pki/signer-p256}
     * @param path the path relative to the corpus
     * @param kind the kind, such as {@code certificate}
     * @param expectedDss the expected DSS result: {@code rejected}, or the indication with its
     *        sub-indication after a space when there is one
     * @param chain the identifiers of the chain, from the issuer up to the trust anchor
     * @param revocation the identifiers of the CRLs and OCSP responses linked
     * @param covered the covered certificate named by the notes, or {@code null}
     */
    record Artefact(String id, String path, String kind, String expectedDss, List<String> chain,
            List<String> revocation, String covered) {
    }

    /** A basic string or a literal string (TOML 1.0.0) on one line; escapes are kept as written. */
    private static final Pattern STRING = Pattern.compile("^([a-z-]+) = (?:\"(.*)\"|'(.*)')$");
    private static final Pattern DSS_TABLE = Pattern.compile(
            "^expected-dss = \\{ indication = \"([A-Z_-]+)\"(?:, sub-indication = \"([A-Z_]+)\")? \\}$");
    private static final Pattern LIST = Pattern.compile("([a-z]+) = \\[([^\\]]*)\\]");
    private static final Pattern COVERED = Pattern.compile("^Covered certificate: (pki/[a-z0-9-]+)\\.");

    private final Map<String, Artefact> artefacts;

    private Manifest(Map<String, Artefact> artefacts) {
        this.artefacts = artefacts;
    }

    /** Reads the manifest of a corpus directory. */
    static Manifest read(Path corpus) throws IOException {
        Map<String, Artefact> artefacts = new LinkedHashMap<>();
        String text = Files.readString(corpus.resolve("manifest.toml"), StandardCharsets.UTF_8);
        for (String block : text.split("\n\\[\\[artefact\\]\\]\n")) {
            if (!block.startsWith("id = ")) {
                continue;
            }
            Map<String, String> strings = new LinkedHashMap<>();
            String expected = null;
            List<String> chain = List.of();
            List<String> revocation = List.of();
            for (String line : block.split("\n")) {
                Matcher dss = DSS_TABLE.matcher(line);
                if (dss.matches()) {
                    expected = dss.group(2) == null ? dss.group(1) : dss.group(1) + " " + dss.group(2);
                    continue;
                }
                if (line.startsWith("links = {")) {
                    Matcher list = LIST.matcher(line);
                    while (list.find()) {
                        List<String> items = new ArrayList<>();
                        for (String item : list.group(2).split(",")) {
                            items.add(item.strip().replace("\"", ""));
                        }
                        if (list.group(1).equals("chain")) {
                            chain = List.copyOf(items);
                        } else if (list.group(1).equals("revocation")) {
                            revocation = List.copyOf(items);
                        }
                    }
                    continue;
                }
                Matcher string = STRING.matcher(line);
                if (string.matches()) {
                    strings.put(string.group(1), string.group(2) != null ? string.group(2) : string.group(3));
                }
            }
            if (expected == null) {
                expected = strings.get("expected-dss");
            }
            String notes = strings.getOrDefault("notes", "");
            Matcher covered = COVERED.matcher(notes);
            Artefact artefact = new Artefact(strings.get("id"), strings.get("path"), strings.get("kind"), expected,
                    chain, revocation, covered.find() ? covered.group(1) : null);
            artefacts.put(artefact.id(), artefact);
        }
        return new Manifest(artefacts);
    }

    /** Returns the artefact with an identifier. */
    Artefact get(String id) {
        Artefact artefact = artefacts.get(id);
        if (artefact == null) {
            throw new IllegalArgumentException("not in the manifest: " + id);
        }
        return artefact;
    }

    /** Returns the artefacts of a kind, in the order of the manifest. */
    List<Artefact> ofKind(String kind) {
        return artefacts.values().stream().filter(artefact -> artefact.kind().equals(kind)).toList();
    }
}
