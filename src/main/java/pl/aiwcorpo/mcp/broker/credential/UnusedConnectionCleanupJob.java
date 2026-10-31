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

    @Scheduled(initialDelayString = "${broker.retention.orphan-sweep-interval:PT6H}", fixedDelayString = "${broker.retention.orphan-sweep-interval:PT6H}")
    public void orphanSecrets() {
        try {
            OffboardingService.OrphanSweep result = offboarding.sweepOrphanSecrets();
            if (result.deleted() > 0) {
                log.info("Removed {} stored secrets that no connection points at", result.deleted());
            }
        } catch (RuntimeException e) {
            log.warn("Sweep of orphaned secrets failed ({})", e.getClass().getSimpleName());
        }
    }
}
