package pl.aiwcorpo.mcp.broker.api;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import pl.aiwcorpo.mcp.broker.auth.ReplayGuardUnavailableException;
import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.credential.CredentialRequiredException;
import pl.aiwcorpo.mcp.broker.credential.InvalidRequestException;
import pl.aiwcorpo.mcp.broker.credential.SecretRejectedException;
import pl.aiwcorpo.mcp.broker.secret.SecretStoreUnavailableException;
import pl.aiwcorpo.mcp.broker.system.UpstreamUnavailableException;

/**
 * Maps failures to C4 bodies. Exception messages from the JSON parser and the HTTP layer are never
 * logged or returned: they can quote request bodies, and request bodies carry PATs.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    private final String connectUrlBase;

    public ApiExceptionHandler(BrokerProperties properties) {
        String base = properties.portalBaseUrl().toString();
        this.connectUrlBase = (base.endsWith("/") ? base.substring(0, base.length() - 1) : base) + "/connections?system=";
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

    @ExceptionHandler(InvalidRequestException.class)
    ResponseEntity<ApiError> invalidRequest(InvalidRequestException e) {
        return ResponseEntity.badRequest().body(new ApiError("invalid_request", e.getMessage()));
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, MethodArgumentNotValidException.class,
            HandlerMethodValidationException.class, HttpMediaTypeException.class})
    ResponseEntity<ApiError> malformed(Exception e) {
        log.info("Rejected malformed request ({})", e.getClass().getSimpleName());
        return ResponseEntity.badRequest().body(ApiError.of("invalid_request"));
    }

    @ExceptionHandler({NoResourceFoundException.class, HttpRequestMethodNotSupportedException.class})
    ResponseEntity<ApiError> notFound(Exception e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ApiError.of("not_found"));
    }

    @ExceptionHandler({SecretStoreUnavailableException.class, UpstreamUnavailableException.class,
            ReplayGuardUnavailableException.class})
    ResponseEntity<ApiError> unavailable(RuntimeException e) {
        log.warn("Dependency unavailable: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(ApiError.of("upstream_unavailable"));
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<ApiError> internal(Exception e) {
        log.error("Unhandled {} at {}", e.getClass().getName(), e.getStackTrace().length > 0 ? e.getStackTrace()[0] : "?");
        return ResponseEntity.internalServerError().body(ApiError.of("internal_error"));
    }
}
