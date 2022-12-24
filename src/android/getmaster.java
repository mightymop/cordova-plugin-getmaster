package de.mopsdom.getmaster;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.content.Context;

import android.content.pm.ApplicationInfo;
import android.util.Base64;
import android.util.Log;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.stream.Collectors;


import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import de.mopsdom.nslookup.nslookup;

public class getmaster extends CordovaPlugin {

  private static String account_type = "USE";

  private static JSONObject getConfigFile(Context ctx) {

    try {
      int rawDevel = ctx.getResources().getIdentifier("development", "raw", ctx.getPackageName());
      int rawProd = ctx.getResources().getIdentifier("production", "raw", ctx.getPackageName());

      boolean isDebuggable =  ( 0 != ( ctx.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE ) );
      InputStream raw = ctx.getResources().openRawResource(isDebuggable ? rawDevel : rawProd);

      int size = raw.available();
      byte[] buffer = new byte[size];
      raw.read(buffer);
      raw.close();
      String result = new String(buffer);
      return new JSONObject(result);
    } catch (Exception e) {
      Log.e("cordova-plugin-getmaster", "getConfigFile: " + e.getMessage());
      return null;
    }
  }

  private static String getBackend(Context ctx) {
    JSONObject config = getConfigFile(ctx);
    String srv_record =null;
    String backend_url = null;
    ArrayList<String> dnsServers = new ArrayList<>();
    JSONArray arrJson;
    boolean forceSettingsBackendUrl = false;
    try {
      srv_record = config.getJSONObject("api_endpoints").getString("srv_record");
      backend_url = config.getJSONObject("api_endpoints").getString("backend_url");
      forceSettingsBackendUrl = config.getJSONObject("api_endpoints").getBoolean("forceSettingsBackendUrl");

      arrJson = config.getJSONObject("api_endpoints").getJSONArray("custom_dnsserver");
      for (int i = 0; i < arrJson.length(); i++)
        dnsServers.add(arrJson.getString(i));
    } catch (Exception e) {
      Log.e("cordova-plugin-getmaster", "getBackend: " + e.getMessage());
      return null;
    }

    if (forceSettingsBackendUrl && (backend_url != null && backend_url.trim().length() > 0)) {
      return backend_url;
    }

    try {
      nslookup dns = new nslookup();
      if (srv_record != null) {
        JSONObject result = dns.doNslookup(srv_record, "SRV", dnsServers, false);
        if (result != null) {
          JSONObject response = result.has("response")?result.getJSONObject("response"):null;
          if (response!=null) {
            if (response.getString("status").equalsIgnoreCase("success")) {
              JSONArray resultArr = response.has("result")?response.getJSONArray("result"):null;
              if (resultArr!=null && resultArr.length()>0)
              {
                return resultArr.getJSONObject(0).getString("target") + ":" + resultArr.getJSONObject(0).getString("port");
              }
            }
          }
        }
      }
      return null;
    }
    catch (Exception e)
    {
      Log.e("cordova-plugin-getmaster", "getBackend: " + e.getMessage());
      return null;
    }
  }

  private static boolean allowCerts(Context ctx) {
    JSONObject config = getConfigFile(ctx);

    boolean allowAllCerts = false;
    try {

      return config.getJSONObject("api_endpoints").has("allowAllCerts")?config.getJSONObject("api_endpoints").getBoolean("allowAllCerts"):true;

    } catch (Exception e) {
      Log.e("cordova-plugin-getmaster", "getBackend: " + e.getMessage());
      return true;
    }
  }

  private void getUserSecrets(final JSONArray data, final CallbackContext callbackContext) {

    if (data == null || data.length() == 0) {
      callbackContext.error("bad request (parameter)");
      return;
    }


    try {
      JSONArray arr = new JSONArray();

      for (int n=0;n<data.length();n++) {
        String user = data.getString(n);

        String key = null;

        if (!checkForUSEAccount(cordova.getActivity())) {
          if (!retrieveMasterKey(cordova.getActivity())) {
            callbackContext.error("MasterKey konnte nicht geladen werden.");
            return;
          }
        }

        key = getMasterKey(cordova.getActivity());
        if (key == null) {
          callbackContext.error("MasterKey konnte nicht geladen werden.");
          return;
        }

        String result = createUserSecret(key, user);
        JSONObject obj = new JSONObject();
        obj.put("user",user);
        obj.put("key",result);
        arr.put(obj);
      }

      callbackContext.success(arr);

    } catch (Exception e) {
      Log.e("cordova-plugin-getmaster", e.getMessage());
      callbackContext.error(e.getMessage());
    }

  }

  private static void createUSEAccount(Context ctx) {
    try {
      Account account;
      if ((account = getUSEAccount(ctx)) == null) {
        account = new Account("USE", account_type);
      }

      AccountManager accountManager = (AccountManager) ctx.getSystemService(Context.ACCOUNT_SERVICE);
      accountManager.addAccountExplicitly(account, null, null);
    } catch (Exception e) {
      Log.e("cordova-plugin-getmaster", "createUSEAccount: " + e.getMessage(), e);
    }
  }

  private static Account getUSEAccount(Context ctx) {
    try {
      AccountManager am = (AccountManager) ctx.getSystemService(Context.ACCOUNT_SERVICE);
      Account[] accounts = am.getAccountsByType(account_type);
      if (accounts != null && accounts.length > 0) {
        return accounts[0];
      }

      return null;
    } catch (Exception e) {
      Log.e("cordova-plugin-getmaster", "getUSEAccount: " + e.getMessage(), e);
      return null;
    }
  }

  public static boolean checkForUSEAccount(Context ctx) {
    try {
      AccountManager am = (AccountManager) ctx.getSystemService(Context.ACCOUNT_SERVICE);
      Account[] accounts = am.getAccountsByType(account_type);
      if (accounts != null && accounts.length > 0) {
        return true;
      }

      return false;
    } catch (Exception e) {
      Log.e("cordova-plugin-getmaster", "checkForUSEAccount: " + e.getMessage(), e);
      return false;
    }
  }

  private static boolean storeMasterKey(String key, Context ctx) {

    try {
      Account acc;
      if (checkForUSEAccount(ctx)) {
        acc = getUSEAccount(ctx);
        AccountManager accountManager = (AccountManager) ctx.getSystemService(Context.ACCOUNT_SERVICE);
        accountManager.setPassword(acc, key);
        return true;
      } else {
        createUSEAccount(ctx);
        return storeMasterKey(key, ctx);
      }
    } catch (Exception e) {
      Log.e("cordova-plugin-getmaster", "storeMasterKey: " + e.getMessage(), e);
      return false;
    }
  }

  public static String bytesToHex(byte[] bytes) {
    StringBuffer result = new StringBuffer();
    for (byte byt : bytes) result.append(Integer.toString((byt & 0xff) + 0x100, 16).substring(1));
    return result.toString();
  }

  public static String createUserSecret(String key, String user) {

    try {
      String input = new StringBuilder(user).reverse().toString() + key + user;
      byte[] buff = input.getBytes(StandardCharsets.UTF_8);
      String b64 = Base64.encodeToString(buff,Base64.NO_WRAP);
      byte[] bytes = b64.getBytes(StandardCharsets.UTF_8);

      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] crypto = digest.digest(bytes);
      String strhash = bytesToHex(crypto);

      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

      int iterations = 300;
      PBEKeySpec pbeKeySpec = new PBEKeySpec(strhash.toCharArray(), user.getBytes(StandardCharsets.UTF_8), iterations, 256);
      Key secretKey = factory.generateSecret(pbeKeySpec);
      byte[] resbytes = new byte[32];
      System.arraycopy(secretKey.getEncoded(), 0, resbytes, 0, 32);
      String result = Base64.encodeToString(resbytes, Base64.NO_WRAP).trim();
      return result;
    } catch (Exception e) {
      Log.e("cordova-plugin-getmaster", "createUserSecret: " + e.getMessage(), e);
      return null;
    }
  }

  public static String getMasterKey(Context ctx) {
    try {
      if (checkForUSEAccount(ctx)) {
        Account acc = getUSEAccount(ctx);
        if (acc==null)
        {
          return null;
        }
        AccountManager accountManager = (AccountManager) ctx.getSystemService(Context.ACCOUNT_SERVICE);
        return accountManager.getPassword(acc);
      } else {
        return null;
      }
    } catch (Exception e) {
      Log.e("cordova-plugin-getmaster", "getMasterKey: " + e.getMessage(), e);
      return null;
    }
  }

  public static String trimEnd( String s,  String suffix) {

    if (s.endsWith(suffix)) {
      return s.substring(0, s.length() - suffix.length());
    }
    return s;
  }

  private static String retrieveMasterKeyFromServer(Context ctx) {

    String hostname_port = getBackend(ctx);
    boolean allowAllCerts = allowCerts(ctx);

    if (allowAllCerts) {
      TrustManager[] trustAllCerts = new TrustManager[]{
        new X509TrustManager() {
          public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return null;
          }

          public void checkClientTrusted(
            java.security.cert.X509Certificate[] certs, String authType) {
          }

          public void checkServerTrusted(
            java.security.cert.X509Certificate[] certs, String authType) {
          }
        }
      };

      try {
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        // Create all-trusting host name verifier
        HostnameVerifier allHostsValid = new HostnameVerifier() {
          public boolean verify(String hostname, SSLSession session) {
            return true;
          }
        };

        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
      } catch (Exception e) {
        Log.e("cordova-plugin-getmaster", "retrieveMasterKey: " + e.getMessage());
        return null;
      }
    }


    try {

      URL url;
      HttpsURLConnection urlConnection = null;
      String urlstr = "https://"+hostname_port+"/use_service/datadownload/getmaster";

      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] encodedhash = digest.digest(ctx.getPackageName().getBytes(StandardCharsets.UTF_8));
      String hashedPackageId = bytesToHex(encodedhash);

      JSONObject param = new JSONObject();
      param.put("token",hashedPackageId);

      url = new URL(urlstr);

      urlConnection = (HttpsURLConnection) url.openConnection();

      // Create the SSL connection
      if (!allowAllCerts) {
        SSLContext sc;
        sc = SSLContext.getInstance("TLS");
        sc.init(null, null, new java.security.SecureRandom());
        urlConnection.setSSLSocketFactory(sc.getSocketFactory());
      }

      // set Timeout and method
      urlConnection.setReadTimeout(7000);
      urlConnection.setConnectTimeout(7000);
      urlConnection.setRequestMethod("POST");
      urlConnection.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
      urlConnection.setRequestProperty("Accept", "application/json");
      urlConnection.setDoInput(true);
      urlConnection.setDoOutput(true);

      urlConnection.connect();

      OutputStream os = urlConnection.getOutputStream();
      os.write(param.toString().getBytes("UTF-8"));
      os.close();

      if (urlConnection.getResponseCode() < 200 || urlConnection.getResponseCode() > 201)
        return null;

      InputStream in = urlConnection.getInputStream();

      String result = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8)).lines().collect(Collectors.joining(""));

      urlConnection.disconnect();
      return new String(Base64.decode(result.trim().replace("\"",""),Base64.NO_WRAP),"UTF-8");
    }
    catch (Exception e) {
      Log.e("cordova-plugin-getmaster", "retrieveMasterKey: "+e.getMessage());
      return null;
    }
  }

  public static boolean retrieveMasterKey(Context ctx) {
    try {
      String key = retrieveMasterKeyFromServer(ctx);
      if (key == null) {
        Log.e("cordova-plugin-getmaster", "retrieveMasterKey: Key konnte nicht geladen werden");
        return false;
      }

      return storeMasterKey(key, ctx);
    } catch (Exception e) {
      Log.e("cordova-plugin-getmaster", "retrieveMasterKey: " + e.getMessage(), e);
      return false;
    }
  }

  public static void remove(Context context)
  {
    Account acc = getUSEAccount(context);
    if (acc==null)
    {
      return;
    }
    AccountManager accountManager = (AccountManager) context.getSystemService(Context.ACCOUNT_SERVICE);
    accountManager.removeAccountExplicitly(acc);
  }

  public static void init(CallbackContext ctx, Context context){
    if (!getmaster.checkForUSEAccount(context))
    {
      if (getmaster.retrieveMasterKey(context))
      {
        if (ctx!=null) {
          ctx.success();
        }
        return;
      }
      if (ctx!=null) {
        ctx.error("MasterKey konnte nicht geladen werden.");
      }
      return;
    }

    String key = getmaster.getMasterKey(context);
    if (key!=null) {
      if (ctx!=null) {
        ctx.success();
      }
      return;
    }

    if (ctx!=null) {
      ctx.error("MasterKey konnte nicht geladen werden.");
    }
    return;
  }

  @Override
  public boolean execute(final String action, final JSONArray data, final CallbackContext callbackContext) {

    if (action.equals("getUserSecrets")) {
      cordova.getThreadPool().execute(new Runnable() {
        public void run() {
          getUserSecrets(data, callbackContext);
        }
      });

      return true;
    }
    else if (action.equals("init")) {
      cordova.getThreadPool().execute(new Runnable() {
        public void run() {
          init(callbackContext,cordova.getContext());
        }
      });

      return true;
    }

    return false;
  }
}
