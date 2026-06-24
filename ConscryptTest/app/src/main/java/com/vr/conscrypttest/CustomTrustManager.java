package com.vr.conscrypttest;

import android.content.Context;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class CustomTrustManager implements X509TrustManager {

  private final X509TrustManager delegate;

  // Certificate filenames a.crt - q.crt mapped to their raw resource IDs
  private static final String[] CERT_NAMES = {
      "a", "b", "c", "d", "e", "f", "g", "h",
      "i", "j", "k", "l", "m", "n", "o", "p", "q"
  };

  public CustomTrustManager(Context context) throws Exception {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, null); // initialise empty keystore

    for (String name : CERT_NAMES) {
      int resId = context.getResources().getIdentifier(name, "raw", context.getPackageName());
      if (resId == 0) {
        throw new IllegalArgumentException("Missing raw resource: " + name + ".crt");
      }
      InputStream is = context.getResources().openRawResource(resId);
      try {
        Certificate cert = cf.generateCertificate(is);
        keyStore.setCertificateEntry(name, cert);
      } finally {
        is.close();
      }
    }

    TrustManagerFactory tmf = TrustManagerFactory.getInstance(
        TrustManagerFactory.getDefaultAlgorithm()
    );
    tmf.init(keyStore);

    X509TrustManager found = null;
    for (TrustManager tm : tmf.getTrustManagers()) {
      if (tm instanceof X509TrustManager) {
        found = (X509TrustManager) tm;
        break;
      }
    }
    if (found == null) {
      throw new IllegalStateException("No X509TrustManager found");
    }
    this.delegate = found;
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType)
      throws java.security.cert.CertificateException {
    delegate.checkClientTrusted(chain, authType);
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType)
      throws java.security.cert.CertificateException {
    delegate.checkServerTrusted(chain, authType);
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return delegate.getAcceptedIssuers();
  }
}