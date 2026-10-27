package pl.aiwcorpo.mcp.broker.event;

/** Publishes credential.invalidated {sub, system} (C4.3, schemas/credential-invalidated-event.schema.json). */
public interface InvalidationPublisher {

    void invalidated(String sub, String system);
}
