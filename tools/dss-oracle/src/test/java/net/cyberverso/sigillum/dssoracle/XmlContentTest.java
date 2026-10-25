package net.cyberverso.sigillum.dssoracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class XmlContentTest {

    @TempDir
    Path temp;

    private Path file(String name, String xml) throws Exception {
        return Files.writeString(temp.resolve(name), xml);
    }

    @Test
    void documentsThatDifferOnlyInPrefixesAreEqual() throws Exception {
        Path a = file("a.xml", "<r xmlns='urn:r' xmlns:d='urn:d'><d:x d:k='1'>v</d:x></r>");
        Path b = file("b.xml", "<p:r xmlns:p='urn:r' xmlns='urn:d'><x xmlns:q='urn:d' q:k='1'>v</x></p:r>");
        assertEquals(XmlContent.of(a), XmlContent.of(b));
    }

    @Test
    void documentsThatDifferInNamesValuesOrTextAreNotEqual() throws Exception {
        Path base = file("base.xml", "<r xmlns='urn:r'><x k='1'>v</x></r>");
        for (String other : new String[] {
            "<r xmlns='urn:other'><x k='1'>v</x></r>",
            "<r xmlns='urn:r'><x k='2'>v</x></r>",
            "<r xmlns='urn:r'><x k='1'>w</x></r>",
            "<r xmlns='urn:r'><y k='1'>v</y></r>"}) {
            assertNotEquals(XmlContent.of(base), XmlContent.of(file("other.xml", other)), other);
        }
    }
}
