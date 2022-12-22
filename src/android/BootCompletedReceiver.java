package de.mopsdom.getmaster;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public class BootCompletedReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
      if (intent.getAction().equalsIgnoreCase(Intent.ACTION_BOOT_COMPLETED)||
        intent.getAction().equalsIgnoreCase(Intent.ACTION_PACKAGE_ADDED)||
        intent.getAction().equalsIgnoreCase(Intent.ACTION_PACKAGE_REPLACED)||
        intent.getAction().equalsIgnoreCase(Intent.ACTION_PACKAGE_FIRST_LAUNCH)) {
        getmaster.init(null, context);
      }

      if (intent.getAction().equalsIgnoreCase(Intent.ACTION_PACKAGE_DATA_CLEARED)||
		  intent.getAction().equalsIgnoreCase(Intent.ACTION_PACKAGE_REMOVED)||
          intent.getAction().equalsIgnoreCase(Intent.ACTION_PACKAGE_FULLY_REMOVED)) {
        getmaster.remove(context);
      }

    }
}
