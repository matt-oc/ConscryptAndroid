package com.vr.conscrypttest;

import android.os.Bundle;
import android.util.Log;

import org.conscrypt.Conscrypt;

import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import androidx.appcompat.app.AppCompatActivity;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.ConnectionSpec;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import static android.webkit.ConsoleMessage.MessageLevel.LOG;

public class App extends AppCompatActivity {
  private CustomTrustManager trustManager;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    // Init Conscrypt
    super.onCreate(savedInstanceState);
    Provider conscrypt = Conscrypt.newProvider();
    try {
      trustManager = new CustomTrustManager(getApplicationContext());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    String LOG = "LOGGING>>>>";

// Add as provider
    Security.insertProviderAt(conscrypt, 1);

    // Init OkHttp
    OkHttpClient.Builder okHttpBuilder = new OkHttpClient()
        .newBuilder()
        .connectionSpecs(Collections.singletonList(ConnectionSpec.RESTRICTED_TLS));

// OkHttp 3.12.x
// ConnectionSpec.COMPATIBLE_TLS = TLS1.0
// ConnectionSpec.MODERN_TLS = TLS1.0 + TLS1.1 + TLS1.2 + TLS 1.3
// ConnectionSpec.RESTRICTED_TLS = TLS 1.2 + TLS 1.3

// OkHttp 3.13+
// ConnectionSpec.COMPATIBLE_TLS = TLS1.0 + TLS1.1 + TLS1.2 + TLS 1.3
// ConnectionSpec.MODERN_TLS = TLS1.2 + TLS 1.3
// ConnectionSpec.RESTRICTED_TLS = TLS 1.2 + TLS 1.3

    try {
      SSLContext sslContext = SSLContext.getInstance("TLS", conscrypt);
      sslContext.init(null, new TrustManager[]{trustManager}, null);
      okHttpBuilder.sslSocketFactory(new InternalSSLSocketFactory(sslContext.getSocketFactory()), trustManager);
    } catch (Exception e) {
      e.printStackTrace();
    }

    // Build OkHttp
    OkHttpClient okHttpClient = okHttpBuilder.build();

    Request request = new Request.Builder()
        .url("https://api.dojo.tech/terminals") // You can try another TLS 1.3 capable HTTPS server
        .build();

    okHttpClient.newCall(request)
        .enqueue(new Callback() {
          @Override
          public void onFailure(final Call call, IOException e) {
            e.printStackTrace();
            Log.d(LOG, "onFailure()");
          }

          @Override
          public void onResponse(Call call,final Response response) throws IOException {
            Log.d(LOG, "onResponse() tlsVersion=" + response.handshake().tlsVersion());
            Log.d(LOG, "onResponse() cipherSuite=" + response.handshake().cipherSuite().toString());
            // D/TestApp##: onResponse() tlsVersion=TLS_1_3
            // D/TestApp##: onResponse() cipherSuite=TLS_AES_256_GCM_SHA384
          }
        });
  }
}
