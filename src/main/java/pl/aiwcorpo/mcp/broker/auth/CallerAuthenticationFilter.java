package pl.aiwcorpo.mcp.broker.auth;

import java.io.IOException;
import java.time.Clock;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import pl.aiwcorpo.mcp.broker.api.ApiError;
import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import tools.jackson.databind.json.JsonMapper;

/**
 * Authenticates every request before it reaches a controller (C4):
 * <ol>
 * <li>the operation must be one this version serves, otherwise 404;</li>
 * <li>the client certificate CN must be allowed for that operation ({@code x-allowed-client-cn}), otherwise 403;</li>
 * <li>the bearer token must match the CN: internal JWT (C2) for mcp-gateway, IdP token for mcp-portal-bff,
 * otherwise 401.</li>
 * </ol>
 * The resulting {@link Caller} is the only source of the user's identity for the controllers.
 */
public class CallerAuthenticationFilter extends OncePerRequestFilter {

    public static final String CALLER = "pl.aiwcorpo.mcp.broker.caller";
    public static final String REQUEST_ID_HEADER = "X-Request-Id";

    private static final Logger log = LoggerFactory.getLogger(CallerAuthenticationFilter.class);

    private final InternalJwtVerifier gatewayTokens;
    private final BffTokenVerifier bffTokens;
    private final AuditLog audit;
    private final JsonMapper json;
    private final Clock clock;
    private final long maxRequestBytes;

    public CallerAuthenticationFilter(InternalJwtVerifier gatewayTokens, BffTokenVerifier bffTokens, AuditLog audit,
            JsonMapper json, Clock clock, long maxRequestBytes) {
        this.gatewayTokens = gatewayTokens;
        this.bffTokens = bffTokens;
        this.audit = audit;
        this.json = json;
        this.clock = clock;
        this.maxRequestBytes = maxRequestBytes;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String headerRequestId = request.getHeader(REQUEST_ID_HEADER);
        String requestId = RequestIds.isValid(headerRequestId) ? headerRequestId : RequestIds.next(clock);
        response.setHeader(REQUEST_ID_HEADER, requestId);
        MDC.put("requestId", requestId);
        try {
            authenticate(request, response, chain, headerRequestId, requestId);
        } finally {
            MDC.remove("requestId");
        }
    }

    private void authenticate(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            String headerRequestId, String requestId) throws ServletException, IOException {
        String path = request.getRequestURI();
        Optional<String> cn = ClientCertificates.commonName(request);
        if (cn.isEmpty()) {
            write(response, 401, "unauthenticated");
            return;
        }
        if (isHealth(request.getMethod(), path)) {
            chain.doFilter(request, response);
            return;
        }
        Optional<Operation> match = Operation.match(request.getMethod(), path);
        if (match.isEmpty()) {
            write(response, 404, "not_found");
            return;
        }
        Operation operation = match.get();
        if (!operation.allowedCns().contains(cn.get())) {
            log.warn("Client certificate CN {} is not allowed for {}", cn.get(), operation.operationId());
            write(response, 403, "forbidden");
            return;
        }
        if (request.getContentLengthLong() > maxRequestBytes) {
            write(response, 400, "invalid_request");
            return;
        }
        Caller caller;
        try {
            String token = bearer(request.getHeader("Authorization"));
            caller = switch (cn.get()) {
                case Operation.GATEWAY -> new Caller.Gateway(requestId,
                        gatewayTokens.verify(token, headerRequestId, operation.serviceVariantAllowed()));
                case Operation.PORTAL_BFF -> bffTokens.verify(token, requestId);
                case Operation.OFFBOARDING -> new Caller.Offboarding(requestId);
                default -> throw new TokenRejectedException("no_token_scheme_for_cn");
            };
        } catch (TokenRejectedException e) {
            log.warn("Rejected token from {} for {}: {}", cn.get(), operation.operationId(), e.reason());
            if (operation.auditEvent() != null) {
                audit.event(operation.auditEvent(), requestId).denied(e.reason(), "unauthenticated");
            }
            write(response, 401, "unauthenticated");
            return;
        } catch (ReplayGuardUnavailableException e) {
            log.warn("Token from {} not checked for replay: {}", cn.get(), e.getMessage());
            if (operation.auditEvent() != null) {
                audit.event(operation.auditEvent(), requestId).error("jti_store_unavailable", "upstream_unavailable");
            }
            write(response, 503, "upstream_unavailable");
            return;
        }
        request.setAttribute(CALLER, caller);
        chain.doFilter(request, response);
    }

    private static boolean isHealth(String method, String path) {
        return "GET".equals(method) && (path.equals("/actuator/health") || path.startsWith("/actuator/health/"));
    }

    private static String bearer(String authorization) {
        if (authorization == null) {
            return null;
        }
        if (!authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            throw new TokenRejectedException("not_a_bearer_token");
        }
        return authorization.substring(7).trim();
    }

    private void write(HttpServletResponse response, int status, String error) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getOutputStream().write(json.writeValueAsBytes(ApiError.of(error)));
    }
}
