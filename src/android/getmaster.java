package de.mopsdom.sqlitecursor;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.content.Context;
import android.database.CursorWindow;
import android.os.Build;
import android.util.Base64;
import android.util.Log;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONObject;

import java.lang.reflect.Field;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;


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

  private void get(final JSONArray data, final CallbackContext callbackContext) {

    if (data == null || data.length() == 0) {
      callbackContext.error("bad request (parameter)");
      return;
    }


    try {
      int size = Integer.parseInt(data.get(0).toString());

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        Field field = CursorWindow.class.getDeclaredField("sCursorWindowSize");
        field.setAccessible(true);
        field.set(null, size * 1024 * 1024);
      }
    } catch (Exception e) {
      Log.e("cordova-plugin-getmaster", e.getMessage());
    }
    callbackContext.success();
  }

  private static String getBackend()
  {
      nslookup dns = new nslookup();
      String query = "";
      String type = "srv";
      //dns.doNslookup( query, type,ArrayList<String> dnsServers, boolean useFallback)
    return null;
  }

  private void getUserSecret(final JSONArray data, final CallbackContext callbackContext) {

    if (data == null || data.length() == 0) {
      callbackContext.error("bad request (parameter)");
      return;
    }


    try {
      int size = Integer.parseInt(data.get(0).toString());

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        Field field = CursorWindow.class.getDeclaredField("sCursorWindowSize");
        field.setAccessible(true);
        field.set(null, size * 1024 * 1024);
      }
    } catch (Exception e) {
      Log.e("cordova-plugin-getmaster", e.getMessage());
    }
    callbackContext.success();
  }

  private static void createUSEAccount(Context ctx) {
    try {
      Account account;
      if ((account = getUSEAccount(ctx)) == null) {
        account = new Account("USE", account_type);
      }

      AccountManager accountManager = (AccountManager) ctx.getSystemService(Context.ACCOUNT_SERVICE);
      accountManager.addAccountExplicitly(account, null, null);
    }
    catch (Exception e)
    {
      Log.e("cordova-plugin-getmaster","createUSEAccount: "+e.getMessage(),e);
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
    }
    catch (Exception e)
    {
      Log.e("cordova-plugin-getmaster","getUSEAccount: "+e.getMessage(),e);
      return null;
    }
  }

  private static boolean checkForUSEAccount(Context ctx) {
    try {
      AccountManager am = (AccountManager) ctx.getSystemService(Context.ACCOUNT_SERVICE);
      Account[] accounts = am.getAccountsByType(account_type);
      if (accounts != null && accounts.length > 0) {
        return true;
      }

      return false;
    }
    catch (Exception e)
    {
      Log.e("cordova-plugin-getmaster","checkForUSEAccount: "+e.getMessage(),e);
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
    }
    catch (Exception e)
    {
      Log.e("cordova-plugin-getmaster","storeMasterKey: "+e.getMessage(),e);
      return false;
    }
  }

  public static String bytesToHex(byte[] bytes) {
    StringBuffer result = new StringBuffer();
    for (byte byt : bytes) result.append(Integer.toString((byt & 0xff) + 0x100, 16).substring(1));
    return result.toString();
  }

  public static String createUserSecret(String key, String user)
  {

    String input = new StringBuilder(user).reverse().toString()+key+user;

    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] encodedhash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
      String strhash = bytesToHex(encodedhash);

      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithSHA1");

      int iterations = 300;
      PBEKeySpec pbeKeySpec = new PBEKeySpec(strhash.toCharArray(), strhash.getBytes(StandardCharsets.UTF_8), iterations, 256);
      Key secretKey = factory.generateSecret(pbeKeySpec);
      byte[] resultkey = new byte[32];
      System.arraycopy(secretKey.getEncoded(), 0, resultkey, 0, 32);
      String result = Base64.encodeToString(resultkey,Base64.DEFAULT);
      return result;
    }
    catch (Exception e)
    {
      Log.e("cordova-plugin-getmaster","createUserSecret: "+e.getMessage(),e);
      return null;
    }
  }

  private static String getMasterKey(Context ctx) {
    try {
      if (checkForUSEAccount(ctx)) {
          Account acc = getUSEAccount(ctx);
          AccountManager accountManager = (AccountManager) ctx.getSystemService(Context.ACCOUNT_SERVICE);
          return accountManager.getPassword(acc);
      }
      else {
          return null;
      }
    }
    catch (Exception e)
    {
      Log.e("cordova-plugin-getmaster","getMasterKey: "+e.getMessage(),e);
      return null;
    }
  }
/*
  private static String retrieveMasterKeyFromServer(Context ctx) {


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
      }


    HttpsURLConnection urlConnection = null;
    URL url;
    try {
      String urlstr = ctx.getString(R.string.URL_LOGIN_SERVER) + "/login64jwt";
      String params = "user=" + user + "&passwort=" + password + (twofa != null && twofa.trim().length() == 6 ? "&twofa=" + twofa : "");

      String paramdata = null;

      byte[] data = params.getBytes("utf-8");
      String base64 = Base64.encodeToString(data, Base64.URL_SAFE);
      base64 = trimEnd(base64, "=").replace('+', '-').replace('/', '_');
      paramdata = "data=" + base64;//URLEncoder.encode(new String(base64),"utf-8");

           // if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.O){
             //   paramdata="data="+URLEncoder.encode(new String(java.util.Base64.getEncoder().encode(params.getBytes("utf-8"))),"utf-8");
            //}
            //else
            //{
             //   byte[] data = params.getBytes("utf-8");
              //  String base64 = Base64.encodeToString(data, Base64.URL_SAFE);

                //paramdata="data="+URLEncoder.encode(new String(base64),"utf-8");
            //}

      url = new URL(urlstr);

      urlConnection = (HttpsURLConnection) url.openConnection();

      // Create the SSL connection
      if (!allowallcerts) {
        SSLContext sc;
        sc = SSLContext.getInstance("TLS");
        sc.init(null, null, new java.security.SecureRandom());
        urlConnection.setSSLSocketFactory(sc.getSocketFactory());
      }

      // set Timeout and method
      urlConnection.setReadTimeout(7000);
      urlConnection.setConnectTimeout(7000);
      urlConnection.addRequestProperty("Content-Type", "application/x-www-form-urlencoded");
      urlConnection.addRequestProperty("Content-Length", String.valueOf(paramdata.length()));
      urlConnection.setRequestMethod("POST");
      urlConnection.setDoInput(true);
      urlConnection.setDoOutput(true);
      PrintWriter out = new PrintWriter(urlConnection.getOutputStream());
      out.print(paramdata);
      out.flush();

      // Add any data you wish to post here
      urlConnection.connect();

      if (urlConnection.getResponseCode() < 200 || urlConnection.getResponseCode() > 201)
        return null;

      String result = "";
      BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));

      String inputLine;
      while ((inputLine = in.readLine()) != null) {
        result += inputLine;
      }
      out.close();

      urlConnection.disconnect();

            //String authField = urlConnection.getHeaderField("Authorization").trim();

            //return authField.split("\\s")[1];

      JSONObject json = null;
      json = new JSONObject(result);

      if (json.has("result") && !json.getBoolean("result"))
        throw new Exception(json.getString("message"));
      else if (json.has("access_token")) {
        return json.getString("access_token");
      } else
        throw new Exception("NO TOKEN DELIVERED!");

    } finally {
      if (urlConnection != null) {
        try {
          urlConnection.disconnect();
        } catch (Exception e) {
        }
      }
    }
  }
*/
  public static boolean retrieveMasterKey(Context ctx) {
    try {
      String key =  null;//retrieveMasterKeyFromServer(ctx);
      if (key==null) {
        Log.e("cordova-plugin-getmaster","retrieveMasterKey: Key konnte nicht geladen werden");
        return false;
      }

      return storeMasterKey(key,ctx);
    }
    catch (Exception e)
    {
      Log.e("cordova-plugin-getmaster","retrieveMasterKey: "+e.getMessage(),e);
      return false;
    }
  }


  @Override
  public boolean execute(final String action, final JSONArray data, final CallbackContext callbackContext) {

    if (action.equals("get")) {

      cordova.getThreadPool().execute(new Runnable() {
        public void run() {
          get(data, callbackContext);
        }
      });

      return true;
    }

    return false;
  }
}
