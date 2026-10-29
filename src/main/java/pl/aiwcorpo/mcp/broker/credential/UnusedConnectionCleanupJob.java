package pl.aiwcorpo.mcp.broker.credential;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;

/** Runs the cleanup of unused connections (CC-155) on the interval of {@code broker.retention.cleanup-interval}. */
public class UnusedConnectionCleanupJob {

    private static final Logger log = LoggerFactory.getLogger(UnusedConnectionCleanupJob.class);

    private final OffboardingService offboarding;

    public UnusedConnectionCleanupJob(OffboardingService offboarding) {
        this.offboarding = offboarding;
    }

    @Scheduled(initialDelayString = "${broker.retention.cleanup-interval:PT1H}", fixedDelayString = "${broker.retention.cleanup-interval:PT1H}")
    public void run() {
        try {
            int removed = offboarding.removeUnused();
            if (removed > 0) {
                log.info("Removed {} unused connections", removed);
            }
        } catch (RuntimeException e) {
            log.warn("Cleanup of unused connections failed ({})", e.getClass().getSimpleName());
        }
    }
}
