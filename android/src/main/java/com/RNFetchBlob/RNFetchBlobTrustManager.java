package com.RNFetchBlob;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.*;
import java.util.Arrays;
import java.util.List;

/**
 * A custom X509TrustManager implementation that trusts a specified server certificate in addition
 * to those that are in the system TrustStore.
 */
public class RNFetchBlobTrustManager implements X509TrustManager {

    private final X509TrustManager originalX509TrustManager;
    private Boolean trustSystem;
    private final KeyStore trustStore;

    /**
     * @param trustStore A KeyStore containing the server certificate that should be trusted
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    public RNFetchBlobTrustManager(boolean trustSystem, KeyStore trustStore) throws NoSuchAlgorithmException, KeyStoreException {
        this.trustSystem = trustSystem;
        this.trustStore = trustStore;

        TrustManagerFactory originalTrustManagerFactory = TrustManagerFactory.getInstance("X509");
        originalTrustManagerFactory.init((KeyStore) null);

        TrustManager[] originalTrustManagers = originalTrustManagerFactory.getTrustManagers();
        originalX509TrustManager = (X509TrustManager) originalTrustManagers[0];
    }

    /**
     * No-op. Never invoked by client, only used in server-side implementations
     * @return
     */
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    /**
     * No-op. Never invoked by client, only used in server-side implementations
     * @return
     */
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
    }

    private void doCustomCheck(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        CertificateFactory factory = CertificateFactory.getInstance("X509");
        CertPath certPath = factory.generateCertPath(Arrays.asList(chain));
        PKIXParameters params = new PKIXParameters(trustStore);
        params.setRevocationEnabled(false);
        validator.validate(certPath, params);
    }

    /**
     * Given the partial or complete certificate chain provided by the peer,
     * build a certificate path to a trusted root and return if it can be validated and is trusted
     * for client SSL authentication based on the authentication type. The authentication type is
     * determined by the actual certificate used. For instance, if RSAPublicKey is used, the authType should be "RSA".
     * Checking is case-sensitive.
     * If `trustSystem` is set, defers to the default trust manager first, checks the cert supplied in the ctor if
     * that fails.
     * @param chain the server's certificate chain
     * @param authType the authentication type based on the client certificate
     * @throws java.security.cert.CertificateException
     */
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
        if (this.trustSystem) {
            try {
                originalX509TrustManager.checkServerTrusted(chain, authType);
            } catch(CertificateException originalException) {
                try {
                    this.doCustomCheck(chain, authType);
                } catch(Exception ex) {
                    throw originalException;
                }
            }
        } else {
            this.doCustomCheck(chain, authType);
        }
    }
}
