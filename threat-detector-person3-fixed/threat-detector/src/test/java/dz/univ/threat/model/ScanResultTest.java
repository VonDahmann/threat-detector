// Tests for the improved shared contract ScanResult (same package as the class it tests).
package dz.univ.threat.model;

import org.junit.jupiter.api.Test;   // marks a method as a JUnit 5 test

import java.util.ArrayList;          // a normal, MODIFIABLE list: used to try to "cheat" immutability
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;   // assertEquals, assertTrue, assertThrows...

class ScanResultTest {

    // A dummy item reused by the tests below.
    private final ScanItem item = new ScanItem(1, InputType.MESSAGE, "hello");

    @Test
    void reasonsAreCopied_laterChangesDoNotAffectTheResult() {
        // Build a modifiable list with one reason...
        List<String> mine = new ArrayList<>(List.of("a"));
        ScanResult r = new ScanResult(item, RiskLevel.LOW, 0, mine, null);
        // ...then change OUR list after creating the result.
        mine.add("b");
        // The result must still contain only "a" (it kept its own private copy).
        assertEquals(List.of("a"), r.reasons());
    }

    @Test
    void reasonsCannotBeModifiedFromOutside() {
        ScanResult r = new ScanResult(item, RiskLevel.LOW, 0, List.of("a"), null);
        // Trying to add to the list inside the result must throw: it is unmodifiable.
        assertThrows(UnsupportedOperationException.class, () -> r.reasons().add("x"));
    }

    @Test
    void nullReasons_becomeEmptyList() {
        ScanResult r = new ScanResult(item, RiskLevel.LOW, 0, null, null);
        // No NullPointerException later when the UI loops over the reasons.
        assertNotNull(r.reasons());
        assertTrue(r.reasons().isEmpty());
    }

    @Test
    void notVerified_hasLevelNotVerified_scoreZero_andTheMessage() {
        ScanResult r = ScanResult.notVerified(item, "Empty input");
        assertEquals(RiskLevel.NOT_VERIFIED, r.level());   // never LOW
        assertEquals(0, r.score());
        assertEquals("Empty input", r.error());
        assertEquals(List.of("Empty input"), r.reasons()); // visible in the UI tooltip
    }

    @Test
    void notVerified_withNullOrBlankMessage_usesDefaultMessage() {
        // A null message...
        assertEquals("Could not be verified", ScanResult.notVerified(item, null).error());
        // ...and a message with only spaces both fall back to the default text.
        assertEquals("Could not be verified", ScanResult.notVerified(item, "   ").error());
    }
}
