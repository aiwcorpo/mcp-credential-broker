package pl.aiwcorpo.mcp.broker.authenticator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;

/** Removes the seeds of enrollments nobody confirmed within their 10 minutes, and seeds no row accounts for. */
public class AuthenticatorSweepJob {

    private static final Logger log = LoggerFactory.getLogger(AuthenticatorSweepJob.class);

    private final AuthenticatorService authenticator;

    public AuthenticatorSweepJob(AuthenticatorService authenticator) {
        this.authenticator = authenticator;
    }

    @Scheduled(initialDelayString = "${broker.authenticator.sweep-interval:PT1M}",
            fixedDelayString = "${broker.authenticator.sweep-interval:PT1M}")
    public void expiredEnrollments() {
        try {
            authenticator.sweepExpiredEnrollments();
        } catch (RuntimeException e) {
            log.warn("Authenticator enrollment sweep failed ({})", e.getClass().getSimpleName());
        }
    }

    @Scheduled(initialDelayString = "${broker.authenticator.orphan-sweep-interval:PT30M}",
            fixedDelayString = "${broker.authenticator.orphan-sweep-interval:PT30M}")
    public void orphanSeeds() {
        try {
            int removed = authenticator.sweepOrphanSeeds();
            if (removed > 0) {
                log.info("Removed {} authenticator seeds without a registration or enrollment", removed);
            }
        } catch (RuntimeException e) {
            log.warn("Authenticator orphan sweep failed ({})", e.getClass().getSimpleName());
        }
    }
}
