package pl.aiwcorpo.mcp.broker.api;

import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.ValueDeserializer;

/**
 * A boolean field that may be left out but not be null: the contract types it as boolean, so an explicit null is a malformed
 * request (400) and not a silent false.
 */
final class StrictBoolean extends ValueDeserializer<Boolean> {

    @Override
    public Boolean deserialize(JsonParser parser, DeserializationContext context) {
        JsonToken token = parser.currentToken();
        if (token == JsonToken.VALUE_TRUE || token == JsonToken.VALUE_FALSE) {
            return token == JsonToken.VALUE_TRUE;
        }
        return context.reportInputMismatch(Boolean.class, "expected true or false");
    }

    @Override
    public Object getNullValue(DeserializationContext context) {
        return context.reportInputMismatch(Boolean.class, "null is not a boolean");
    }

    @Override
    public Object getAbsentValue(DeserializationContext context) {
        return null;
    }
}
