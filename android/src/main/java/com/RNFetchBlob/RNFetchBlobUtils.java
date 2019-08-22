package com.RNFetchBlob;

import android.content.res.AssetManager;
import android.content.Context;
import android.util.Log;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.modules.core.DeviceEventManagerModule;

import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.io.*;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;

import okhttp3.OkHttpClient;


public class RNFetchBlobUtils {

    public static String getMD5(String input) {
        String result = null;

        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(input.getBytes());
            byte[] digest = md.digest();

            StringBuilder sb = new StringBuilder();

            for (byte b : digest) {
                sb.append(String.format("%02x", b & 0xff));
            }

            result = sb.toString();
        } catch (Exception ex) {
            ex.printStackTrace();
        } finally {
            // TODO: Is discarding errors the intent? (https://www.owasp.org/index.php/Return_Inside_Finally_Block)
            return result;
        }

    }

    public static void emitWarningEvent(String data) {
        WritableMap args = Arguments.createMap();
        args.putString("event", "warn");
        args.putString("detail", data);

        // emit event to js context
        RNFetchBlob.RCTContext.getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
                .emit(RNFetchBlobConst.EVENT_MESSAGE, args);
    }

    public static OkHttpClient.Builder getUnsafeOkHttpClient(OkHttpClient client) {
        try {
            // Create a trust manager that does not validate certificate chains
            final TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
                        }

                        @Override
                        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
                        }

                        @Override
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return new java.security.cert.X509Certificate[]{};
                        }
                    }
            };

            // Install the all-trusting trust manager
            final SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            // Create an ssl socket factory with our all-trusting manager
            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            OkHttpClient.Builder builder = client.newBuilder();
            builder.sslSocketFactory(sslSocketFactory);
            builder.hostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            });

            return builder;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static OkHttpClient.Builder getClientCertificateOkHttpClient(String clientCertificate, String clientCertificatePassword, OkHttpClient client) {
        try {
            Log.i("TOBY", "in getClientCertificateOkHttpClient");
            Context appCtx = RNFetchBlob.RCTContext.getApplicationContext();
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            AssetManager assetManager = appCtx.getAssets();
            InputStream fis = assetManager.open(clientCertificate);
            keyStore.load(fis, clientCertificatePassword.toCharArray());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509");
            kmf.init(keyStore, clientCertificatePassword.toCharArray());

            KeyManager[] keyManagers = kmf.getKeyManagers();

            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(keyManagers, null, new java.security.SecureRandom());

            // Create an ssl socket factory with our all-trusting manager
            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            OkHttpClient.Builder builder = client.newBuilder();
            builder.sslSocketFactory(sslSocketFactory);
            // builder.hostnameVerifier(new HostnameVerifier() {
            //     @Override
            //     public boolean verify(String hostname, SSLSession session) {
            //         return true;
            //     }
            // });

            return builder;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Produces a KeyStore from a String containing a PEM certificate (typically, the server's CA certificate)
     * @param certificateString A String containing the PEM-encoded certificate
     * @return a KeyStore (to be used as a trust store) that contains the certificate
     * @throws Exception
     */
    private static KeyStore loadPEMTrustStore(String certificateString) throws Exception {

        byte[] der = loadPemCertificate(new ByteArrayInputStream(certificateString.getBytes()));
        ByteArrayInputStream derInputStream = new ByteArrayInputStream(der);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(derInputStream);
        String alias = cert.getSubjectX500Principal().getName();

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null);
        trustStore.setCertificateEntry(alias, cert);

        return trustStore;
    }

    /**
     * Reads and decodes a base-64 encoded DER certificate (a .pem certificate), typically the server's CA cert.
     * @param certificateStream an InputStream from which to read the cert
     * @return a byte[] containing the decoded certificate
     * @throws IOException
     */
    private static byte[] loadPemCertificate(InputStream certificateStream) throws IOException {

        byte[] der = null;
        BufferedReader br = null;

        try {
            StringBuilder buf = new StringBuilder();
            br = new BufferedReader(new InputStreamReader(certificateStream));

            String line = br.readLine();
            while(line != null) {
                if(!line.startsWith("--")){
                    buf.append(line);
                }
                line = br.readLine();
            }

            String pem = buf.toString();
            der = Base64.decode(pem, Base64.DEFAULT);

        } finally {
           if(br != null) {
               br.close();
           }
        }

        return der;
    }

    /**
     * Produces a KeyStore from a PKCS12 (.p12) certificate file, typically the client certificate
     * @param p12Base64 The base64-encoded p12 file.
     * @param clientCertPassword Password for the certificate
     * @return A KeyStore containing the certificate from the certificateFile
     * @throws Exception
     */
    private static KeyStore loadPKCS12KeyStore(String p12Base64, String clientCertPassword) throws Exception {
        KeyStore keyStore = null;
        byte[] p12Decoded = Base64.decode(p12Base64, Base64.DEFAULT);
        InputStream fis = new ByteArrayInputStream(p12Decoded);
        try {
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(fis, clientCertPassword.toCharArray());
        } finally {
            try {
                if(fis != null) {
                    fis.close();
                }
            } catch(IOException ex) {
                // ignore
            }
        }
        return keyStore;
    }

    public static OkHttpClient.Builder getClientCertCAOkHttpClient(String caCertificate, String p12Base64ClientCertificate, String clientCertificatePassword, OkHttpClient client) {
        try {
            Log.i("TOBY", "in getClientCertCAOkHttpClient");

            // Create a trust store from the CA certificate.
            KeyStore trustStore = loadPEMTrustStore(caCertificate);
            TrustManager[] trustManagers = {new RNFetchBlobTrustManager(trustStore)};

            // Load the client certificate.
            KeyStore keyStore = loadPKCS12KeyStore(p12Base64ClientCertificate, clientCertificatePassword);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509");
            kmf.init(keyStore, clientCertificatePassword.toCharArray());
            KeyManager[] keyManagers = kmf.getKeyManagers();

            // Create a context using the custom key and trust managers.
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagers, trustManagers, null);

            // Create an ssl socket factory with our all-trusting manager
            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            OkHttpClient.Builder builder = client.newBuilder();
            builder.sslSocketFactory(sslSocketFactory);
            // builder.hostnameVerifier(new HostnameVerifier() {
            //     @Override
            //     public boolean verify(String hostname, SSLSession session) {
            //         return true;
            //     }
            // });

            return builder;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
