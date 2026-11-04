package pl.aiwcorpo.mcp.broker.support;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Throwaway internal CA for the integration tests, shaped like the dev stack: EC P-256, CN=&lt;name&gt;,
 * EKU per role (the broker certificate is serverAuth only, client identities are clientAuth only).
 */
public final class TestPki {

    public static final char[] PASSWORD = "test-only-store-password".toCharArray();

    public record Identity(KeyPair keys, X509Certificate certificate, X509Certificate issuer) {
    }

    private final KeyPair caKeys;
    private final X509Certificate caCertificate;

    public TestPki(String caName) {
        try {
            caKeys = ecKeys();
            Instant now = Instant.now();
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(new X500Name("CN=" + caName),
                    serial(), Date.from(now.minus(Duration.ofMinutes(5))), Date.from(now.plus(Duration.ofDays(2))),
                    new X500Name("CN=" + caName), caKeys.getPublic());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            caCertificate = sign(builder, caKeys);
        } catch (GeneralSecurityException | IOException | OperatorCreationException e) {
            throw new IllegalStateException(e);
        }
    }

    public X509Certificate caCertificate() {
        return caCertificate;
    }

    public Identity server(String cn, String... dnsNames) {
        return issue(cn, KeyPurposeId.id_kp_serverAuth, dnsNames);
    }

    public Identity client(String cn) {
        return issue(cn, KeyPurposeId.id_kp_clientAuth);
    }

    private Identity issue(String cn, KeyPurposeId purpose, String... dnsNames) {
        try {
            KeyPair keys = ecKeys();
            Instant now = Instant.now();
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(caCertificate, serial(),
                    Date.from(now.minus(Duration.ofMinutes(5))), Date.from(now.plus(Duration.ofDays(1))),
                    new X500Name("CN=" + cn), keys.getPublic());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purpose));
            if (dnsNames.length > 0) {
                GeneralName[] names = new GeneralName[dnsNames.length];
                for (int i = 0; i < dnsNames.length; i++) {
                    names[i] = new GeneralName(GeneralName.dNSName, dnsNames[i]);
                }
                builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
            }
            return new Identity(keys, sign(builder, caKeys), caCertificate);
        } catch (GeneralSecurityException | IOException | OperatorCreationException e) {
            throw new IllegalStateException(e);
        }
    }

    public static Path writeKeyStore(Identity identity, Path file) {
        try {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(null, null);
            store.setKeyEntry("identity", identity.keys().getPrivate(), PASSWORD,
                    new X509Certificate[] {identity.certificate(), identity.issuer()});
            save(store, file);
            return file;
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public Path writeTrustStore(Path file) {
        try {
            save(trustStore(), file);
            return file;
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Client TLS context presenting {@code identity} and trusting this CA. */
    public SSLContext clientContext(Identity identity) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setKeyEntry("identity", identity.keys().getPrivate(), PASSWORD,
                    new X509Certificate[] {identity.certificate(), identity.issuer()});
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, PASSWORD);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore());
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
            return context;
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private KeyStore trustStore() throws GeneralSecurityException, IOException {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setCertificateEntry("ca", caCertificate);
        return store;
    }

    private static void save(KeyStore store, Path file) throws GeneralSecurityException, IOException {
        try (OutputStream out = Files.newOutputStream(file)) {
            store.store(out, PASSWORD);
        }
    }

    private static KeyPair ecKeys() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static BigInteger serial() {
        return new BigInteger(64, new SecureRandom());
    }

    private static X509Certificate sign(X509v3CertificateBuilder builder, KeyPair issuerKeys)
            throws GeneralSecurityException, OperatorCreationException {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeys.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
