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
}
