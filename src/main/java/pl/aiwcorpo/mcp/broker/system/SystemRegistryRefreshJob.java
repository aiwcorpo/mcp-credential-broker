package pl.aiwcorpo.mcp.broker.system;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;

/** Picks up the changes other instances made to the systems; see {@link SystemRegistry}. */
public class SystemRegistryRefreshJob {

    private static final Logger log = LoggerFactory.getLogger(SystemRegistryRefreshJob.class);

    private final SystemRegistry registry;

    public SystemRegistryRefreshJob(SystemRegistry registry) {
        this.registry = registry;
    }

    @Scheduled(initialDelayString = "${broker.system-sync.interval:PT5S}", fixedDelayString = "${broker.system-sync.interval:PT5S}")
    public void run() {
        try {
            registry.reload();
        } catch (RuntimeException e) {
            log.warn("Systems not refreshed, the previous list stays ({})", e.getClass().getSimpleName());
        }
    }
}
