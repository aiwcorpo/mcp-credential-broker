package pl.aiwcorpo.mcp.broker.auth;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import jakarta.servlet.http.HttpServletRequest;

/** CN of the TLS client certificate. Chain validation and EKU are done by the TLS layer (client-auth=need). */
public final class ClientCertificates {

    private static final String ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    private ClientCertificates() {
    }

    public static Optional<String> commonName(HttpServletRequest request) {
        if (!(request.getAttribute(ATTRIBUTE) instanceof X509Certificate[] chain) || chain.length == 0) {
            return Optional.empty();
        }
        return commonName(chain[0]);
    }

    /** Exactly one CN, otherwise empty: a certificate with two CNs must not be matched on either. */
    static Optional<String> commonName(X509Certificate certificate) {
        try {
            List<Rdn> cns = new LdapName(certificate.getSubjectX500Principal().getName()).getRdns().stream()
                    .filter(rdn -> "CN".equalsIgnoreCase(rdn.getType()))
                    .toList();
            if (cns.size() != 1 || !(cns.getFirst().getValue() instanceof String cn)) {
                return Optional.empty();
            }
            return Optional.of(cn);
        } catch (InvalidNameException e) {
            return Optional.empty();
        }
    }
}
