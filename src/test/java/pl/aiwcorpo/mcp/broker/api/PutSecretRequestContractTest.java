package pl.aiwcorpo.mcp.broker.api;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.broker.support.Contracts;

class PutSecretRequestContractTest {

    @Test
    void theUsernamePatternIsTheOneOfTheContract() {
        String published = Contracts.brokerOpenApi().path("components").path("schemas").path("PutSecretRequest")
                .path("properties").path("username").path("pattern").stringValue();
        assertThat(PutSecretRequest.USERNAME).isEqualTo(published);
    }

    @Test
    void theUsernamePatternKeepsOutColonsInvisibleAndControlCharacters() {
        Pattern pattern = Pattern.compile(PutSecretRequest.USERNAME);
        for (String good : new String[] {"alice", "alice.smith@corp.test", "zoe-o'brien", "o" + (char) 0xf3 + "skar"}) {
            assertThat(pattern.matcher(good).matches()).as(good).isTrue();
        }
        for (int hidden : new int[] {':', 0x200b, 0x07, 0x85, 0x2028, 0x202e, 0xad, 0x3164, 0x34f, 0xfe0f, '\n', 0xd800}) {
            String bad = "a" + (char) hidden + "b";
            assertThat(pattern.matcher(bad).matches()).as("U+%04X", hidden).isFalse();
        }
    }
}
