package pl.aiwcorpo.mcp.broker.config;

import java.util.List;

import org.slf4j.Marker;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.turbo.TurboFilter;
import ch.qos.logback.core.spi.FilterReply;

/**
 * Drops DEBUG and TRACE from the HTTP layer whatever logging.level says. At those levels Spring MVC and
 * Tomcat log request details, and a JSON parse error quotes the body, which for PUT secret is a PAT.
 */
public class HttpLayerDebugGuard extends TurboFilter {

    private static final List<String> PREFIXES = List.of(
            "org.springframework.web", "org.springframework.http", "org.apache.coyote", "org.apache.tomcat",
            "org.apache.catalina", "tools.jackson", "com.fasterxml.jackson");

    @Override
    public FilterReply decide(Marker marker, Logger logger, Level level, String format, Object[] params, Throwable t) {
        if (level == null || level.isGreaterOrEqual(Level.INFO)) {
            return FilterReply.NEUTRAL;
        }
        String name = logger.getName();
        for (String prefix : PREFIXES) {
            if (name.startsWith(prefix)) {
                return FilterReply.DENY;
            }
        }
        return FilterReply.NEUTRAL;
    }
}
