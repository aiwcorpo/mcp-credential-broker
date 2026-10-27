package pl.aiwcorpo.mcp.broker.support;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import com.networknt.schema.Error;
import com.networknt.schema.Schema;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SpecificationVersion;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.dataformat.yaml.YAMLMapper;

/** Access to pl.aiwcorpo.mcp:mcp-contracts (version from pom.xml) and its test-vectors jar on the test classpath. */
public final class Contracts {

    public static final String ROOT = "mcp-contracts/";
    public static final String BROKER_OPENAPI = ROOT + "openapi/bundled/credential-broker.v1.bundled.yaml";
    public static final JsonMapper JSON = JsonMapper.builder().build();

    private static final SchemaRegistry SCHEMAS = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12);

    private Contracts() {
    }

    public static String text(String path) {
        try (InputStream in = Contracts.class.getClassLoader().getResourceAsStream(ROOT + path)) {
            if (in == null) {
                throw new IllegalArgumentException("not on classpath: " + ROOT + path);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static JsonNode json(String path) {
        return JSON.readTree(text(path));
    }

    public static JsonNode brokerOpenApi() {
        try (InputStream in = Contracts.class.getClassLoader().getResourceAsStream(BROKER_OPENAPI)) {
            return new YAMLMapper().readTree(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Resources under test-vectors/&lt;dir&gt;, sorted by name. */
    public static List<Resource> vectors(String dir) {
        try {
            Resource[] found = new PathMatchingResourcePatternResolver()
                    .getResources("classpath*:" + ROOT + "test-vectors/" + dir + "/*.json");
            return Arrays.stream(found).sorted(Comparator.comparing(Resource::getFilename)).toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Errors of a JSON value against a component schema of the C4 OpenAPI (empty = valid). */
    public static List<String> brokerSchemaErrors(String component, JsonNode value) {
        Schema schema = SCHEMAS.getSchema(SchemaLocation.of("classpath:" + BROKER_OPENAPI + "#/components/schemas/" + component));
        return messages(schema.validate(value));
    }

    /** Errors of a JSON value against a JSON Schema file of the contracts, e.g. schemas/audit-event.schema.json. */
    public static List<String> schemaErrors(String schemaPath, JsonNode value) {
        Schema schema = SCHEMAS.getSchema(SchemaLocation.of("classpath:" + ROOT + schemaPath));
        return messages(schema.validate(value));
    }

    private static List<String> messages(List<Error> errors) {
        return errors.stream().map(Error::toString).collect(Collectors.toList());
    }
}
