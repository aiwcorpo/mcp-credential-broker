package pl.aiwcorpo.mcp.broker.credential;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * Renews OAuth access tokens before they expire, so the first resolve after a quiet period does not have to
 * wait for the provider and a grant revoked at the provider shows up as "revoked" in the portal.
 */
public class OAuthRefreshJob {

    private static final Logger log = LoggerFactory.getLogger(OAuthRefreshJob.class);

    private final OAuthService oauth;

    public OAuthRefreshJob(OAuthService oauth) {
        this.oauth = oauth;
    }

    @Scheduled(initialDelayString = "${broker.oauth-flow.sweep-interval:PT1M}", fixedDelayString = "${broker.oauth-flow.sweep-interval:PT1M}")
    public void run() {
        try {
            oauth.refreshDue();
        } catch (RuntimeException e) {
            log.warn("OAuth token sweep failed ({})", e.getClass().getSimpleName());
        }
    }
}
