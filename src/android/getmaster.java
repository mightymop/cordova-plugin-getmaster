package de.mopsdom.getmaster;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.content.Context;

import android.content.pm.ApplicationInfo;
import android.net.Uri;
import android.util.Base64;
import android.util.Log;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.Proxy;
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

public class getmaster extends CordovaPlugin {

  private static String getAccountType(Context ctx)
  {
	  int id_accountType = ctx.getResources().getIdentifier("account_type", "string", ctx.getPackageName());
	  Log.e("cordova-plugin-getmaster",String.valueOf(id_accountType));
    String result = ctx.getResources().getString(id_accountType);
    Log.e("cordova-plugin-getmaster",result);
    return result;
  }

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
    //String srv_record =null;
    String backend_url = null;
   // ArrayList<String> dnsServers = new ArrayList<>();
    JSONArray arrJson;
    boolean forceSettingsBackendUrl = false;
    try {
      //srv_record = config.getJSONObject("api_endpoints").getString("srv_record");
      backend_url = config.getJSONObject("api_endpoints").getString("backend_url");
      //forceSettingsBackendUrl = config.getJSONObject("api_endpoints").getBoolean("forceSettingsBackendUrl");

     /* arrJson = config.getJSONObject("api_endpoints").getJSONArray("custom_dnsserver");
      for (int i = 0; i < arrJson.length(); i++)
        dnsServers.add(arrJson.getString(i));*/
    } catch (Exception e) {
      Log.e("cordova-plugin-getmaster", "getBackend: " + e.getMessage());
      return null;
    }

    if (/*forceSettingsBackendUrl && (*/backend_url != null && backend_url.trim().length() > 0)/*)*/ {
      try {
        URL url = new URL(backend_url);
        return url.getPort()!=-1 ? url.getHost() + ":" + String.valueOf(url.getPort()):url.getHost();
      }catch (Exception e)
      {
        Log.e("cordova-plugin-getmaster",e.getMessage(),e);
        String res = backend_url.replace("https://","").replace("http://","");
        return res.contains("/")?res.substring(0,res.indexOf("/")):res;
      }
    }

	return null;
   /* try {
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
    }*/
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

        String keys = null;

        if (!checkForUSEAccount(cordova.getActivity())) {
          if (!retrieveMasterKeys(cordova.getActivity())) {
            callbackContext.error("MasterKey konnte nicht geladen werden.");
            return;
          }
        }

        keys= getMasterKeys(cordova.getActivity());
        if (keys == null) {
          callbackContext.error("MasterKey konnte nicht geladen werden.");
          return;
        }

        JSONArray jkeys = new JSONArray(keys);
        for (int m=0;m<jkeys.length();m++) {

          String secret = jkeys.getJSONObject(m).getString("secret");
          String result = createUserSecret(secret, user);
          jkeys.getJSONObject(m).put("secret",result);
        }
        JSONObject obj = new JSONObject();
        obj.put("user", user);
        obj.put("secrets", jkeys);
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
        account = new Account("USE", getAccountType(ctx));
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
      Account[] accounts = am.getAccountsByType(getAccountType(ctx));
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
      Account[] accounts = am.getAccountsByType(getAccountType(ctx));
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

  public static String getMasterKeys(Context ctx) {
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

  public static HttpsURLConnection getConnection(Context context, Uri uri, String method) {
    try
    {
      URL url = new URL(uri.toString());

      HttpsURLConnection conn = null;

      conn = (HttpsURLConnection) url.openConnection();

      // Set up the connection properties
      conn.setRequestMethod(method);
      int timeout = 20000;
      conn.setReadTimeout(timeout /* milliseconds */);
      conn.setConnectTimeout(timeout /* milliseconds */);
      conn.setDoInput(true);
      if (method.equalsIgnoreCase("post")) {
        conn.setDoOutput(true);
      }

      return conn;
    } catch (IOException e) {
      Log.e("cordova-plugin-getmaster",e.getMessage());
      return null;
    }
  }

  private static String retrieveMasterKeyFromServer(Context ctx)
  {
    try
    {
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

      HttpsURLConnection urlConnection;
      String urlstr = "https://"+hostname_port+"/use_service/datadownload/getmaster";

      HttpsURLConnection connection = getConnection(ctx, Uri.parse(urlstr),"POST");

      if (!allowAllCerts) {
        SSLContext sc;
        sc = SSLContext.getInstance("TLS");
        sc.init(null, null, new java.security.SecureRandom());
        connection.setSSLSocketFactory(sc.getSocketFactory());
      }

      connection.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
      connection.setRequestProperty("Accept", "application/json");

      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] encodedhash = digest.digest(ctx.getPackageName().getBytes(StandardCharsets.UTF_8));
      String hashedPackageId = bytesToHex(encodedhash);

      JSONObject param = new JSONObject();
      param.put("token",hashedPackageId);

      OutputStream outputStream = connection.getOutputStream();
      BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(outputStream));

      writer.write(param.toString());
      writer.flush();
      writer.close();

      try {
        int respCode = 0;
        if ((respCode=connection.getResponseCode()) == HttpsURLConnection.HTTP_OK) {
          InputStream inputStream = connection.getInputStream();
          BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));

          StringBuilder result = new StringBuilder();
          String line;
          while ((line = reader.readLine()) != null) {
            result.append(line);
          }
          reader.close();
          return new String(Base64.decode(result.toString().trim().replace("\"",""),Base64.NO_WRAP),"UTF-8");
        } else {
          Log.e("cordova-plugin-getmaster", connection.getResponseMessage() + ": " + String.valueOf(respCode));
          return null;
        }
      }
      finally {
        connection.disconnect();
      }

    }
    catch (Exception e)
    {
      Log.e("cordova-plugin-getmaster",e.getMessage(),e);

      return null;
    }
  }

  public static boolean retrieveMasterKeys(Context ctx) {
    try {
      String keys = retrieveMasterKeyFromServer(ctx);
      if (keys == null) {
        Log.e("cordova-plugin-getmaster", "retrieveMasterKey: Key konnte nicht geladen werden");
        return false;
      }

      return storeMasterKey(keys, ctx);
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
      if (getmaster.retrieveMasterKeys(context))
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

    String key = getmaster.getMasterKeys(context);
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
