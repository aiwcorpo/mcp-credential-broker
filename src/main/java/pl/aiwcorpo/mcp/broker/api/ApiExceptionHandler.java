package pl.aiwcorpo.mcp.broker.api;

import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.RecoverableDataAccessException;
import org.springframework.dao.TransientDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.transaction.TransactionException;
import org.springframework.web.HttpMediaTypeException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import jakarta.servlet.http.HttpServletRequest;
import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.auth.Caller;
import pl.aiwcorpo.mcp.broker.auth.CallerAuthenticationFilter;
import pl.aiwcorpo.mcp.broker.auth.Operation;
import pl.aiwcorpo.mcp.broker.authenticator.AuthenticatorRefusedException;
import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.credential.CredentialRequiredException;
import pl.aiwcorpo.mcp.broker.credential.InvalidRequestException;
import pl.aiwcorpo.mcp.broker.credential.RateLimitUnavailableException;
import pl.aiwcorpo.mcp.broker.credential.RateLimitedException;
import pl.aiwcorpo.mcp.broker.credential.SecretRejectedException;
import pl.aiwcorpo.mcp.broker.credential.SystemNotConfiguredException;
import pl.aiwcorpo.mcp.broker.secret.SecretStoreUnavailableException;
import pl.aiwcorpo.mcp.broker.system.ExchangeDeniedException;
import pl.aiwcorpo.mcp.broker.system.UpstreamUnavailableException;

/**
 * Maps failures to C4 bodies (CC-012). Exception messages from the JSON parser and the HTTP layer are never
 * logged or returned: they can quote request bodies, and request bodies carry PATs. Requests rejected
 * before they reach the service are audited here, so every resolve and PUT secret leaves an audit line.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    private final String connectUrlBase;
    private final AuditLog audit;

    public ApiExceptionHandler(BrokerProperties properties, AuditLog audit) {
        String base = properties.portalBaseUrl().toString();
        this.connectUrlBase = (base.endsWith("/") ? base.substring(0, base.length() - 1) : base) + "/connections?system=";
        this.audit = audit;
    }

    @ExceptionHandler(CredentialRequiredException.class)
    ResponseEntity<CredentialRequiredResponse> credentialRequired(CredentialRequiredException e) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new CredentialRequiredResponse("credential_required", e.system(), connectUrlBase + e.system()));
    }

    @ExceptionHandler(SecretRejectedException.class)
    ResponseEntity<Map<String, String>> secretRejected(SecretRejectedException e) {
        return ResponseEntity.status(422).body(Map.of("error", e.error()));
    }

    /** Raised and audited by the services (CC-158). */
    @ExceptionHandler(SystemNotConfiguredException.class)
    ResponseEntity<Map<String, String>> systemNotConfigured(SystemNotConfiguredException e) {
        return ResponseEntity.status(422).body(Map.of("error", "system_not_configured"));
    }

    /** The IdP refused the token exchange; audited by resolve (CC-157). */
    @ExceptionHandler(ExchangeDeniedException.class)
    ResponseEntity<Map<String, String>> exchangeDenied(ExchangeDeniedException e) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "exchange_denied"));
    }

    /** Audited by the service that counted (CC-156). */
    @ExceptionHandler(RateLimitedException.class)
    ResponseEntity<Map<String, String>> rateLimited(RateLimitedException e) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header("Retry-After", String.valueOf(e.retryAfterSeconds()))
                .body(Map.of("error", "rate_limited"));
    }

    /** Raised and audited by the authenticator service: 409, 422 and 429 bodies of C4. */
    @ExceptionHandler(AuthenticatorRefusedException.class)
    ResponseEntity<Map<String, String>> authenticatorRefused(AuthenticatorRefusedException e) {
        ResponseEntity.BodyBuilder response = ResponseEntity.status(e.status());
        if (e.retryAfterSeconds() != null) {
            response.header("Retry-After", String.valueOf(e.retryAfterSeconds()));
        }
        return response.body(Map.of("error", e.error()));
    }

    /** Raised and audited by the service. */
    @ExceptionHandler(InvalidRequestException.class)
    ResponseEntity<ApiError> invalidRequest(InvalidRequestException e) {
        return ResponseEntity.badRequest().body(new ApiError("invalid_request", e.getMessage()));
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, MethodArgumentNotValidException.class,
            HandlerMethodValidationException.class, HttpMediaTypeException.class})
    ResponseEntity<ApiError> malformed(Exception e, HttpServletRequest request) {
        log.info("Rejected malformed request ({})", e.getClass().getSimpleName());
        Optional<Operation> operation = Operation.match(request.getMethod(), request.getRequestURI());
        if (operation.isPresent() && operation.get().auditEvent() != null) {
            AuditLog.Entry entry = audit.event(operation.get().auditEvent(), requestId(request))
                    .system(Operation.systemOf(request.getRequestURI()));
            switch (request.getAttribute(CallerAuthenticationFilter.CALLER)) {
                case Caller.Gateway gateway -> entry.user(gateway.claims().sub(), gateway.claims().usr(), gateway.claims().azp())
                        .gatewayContext(gateway.claims().tool(), gateway.claims().prv());
                case Caller.PortalUser user -> entry.user(user.sub(), user.username(), user.azp());
                case null, default -> {
                }
            }
            entry.denied("invalid_request", "invalid_argument");
        }
        return ResponseEntity.badRequest().body(ApiError.of("invalid_request"));
    }

    @ExceptionHandler({NoResourceFoundException.class, HttpRequestMethodNotSupportedException.class})
    ResponseEntity<ApiError> notFound(Exception e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ApiError.of("not_found_or_denied"));
    }

    @ExceptionHandler({SecretStoreUnavailableException.class, UpstreamUnavailableException.class, RateLimitUnavailableException.class,
            DataAccessResourceFailureException.class, TransientDataAccessException.class,
            RecoverableDataAccessException.class, TransactionException.class})
    ResponseEntity<ApiError> unavailable(RuntimeException e) {
        log.warn("Dependency unavailable: {}", e instanceof SecretStoreUnavailableException || e instanceof UpstreamUnavailableException || e instanceof RateLimitUnavailableException
                ? e.getMessage() : e.getClass().getSimpleName());
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(ApiError.of("upstream_unavailable"));
    }

    /**
     * C4 defines no 500. Anything unexpected is answered like an unavailable dependency, which the gateway
     * already treats as a refusal (fail closed); the log keeps the class and frame for diagnosis.
     */
    @ExceptionHandler(Exception.class)
    ResponseEntity<ApiError> unexpected(Exception e) {
        log.error("Unhandled {} at {}", e.getClass().getName(), e.getStackTrace().length > 0 ? e.getStackTrace()[0] : "?");
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(ApiError.of("upstream_unavailable"));
    }

    private static String requestId(HttpServletRequest request) {
        Object caller = request.getAttribute(CallerAuthenticationFilter.CALLER);
        return caller instanceof Caller c ? c.requestId() : String.valueOf(request.getAttribute(CallerAuthenticationFilter.REQUEST_ID));
    }
}
