package pl.aiwcorpo.mcp.broker.authenticator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;

/** Removes the seeds of enrollments nobody confirmed within their 10 minutes. */
public class AuthenticatorSweepJob {

    private static final Logger log = LoggerFactory.getLogger(AuthenticatorSweepJob.class);

    private final AuthenticatorService authenticator;

    public AuthenticatorSweepJob(AuthenticatorService authenticator) {
        this.authenticator = authenticator;
    }

    @Scheduled(initialDelayString = "${broker.authenticator.sweep-interval:PT1M}",
            fixedDelayString = "${broker.authenticator.sweep-interval:PT1M}")
    public void run() {
        try {
            authenticator.sweepExpiredEnrollments();
        } catch (RuntimeException e) {
            log.warn("Authenticator enrollment sweep failed ({})", e.getClass().getSimpleName());
        }
    }
}
