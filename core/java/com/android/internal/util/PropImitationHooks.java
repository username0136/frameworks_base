/*
 * Copyright (C) 2022 Paranoid Android
 *           (C) 2023 ArrowOS
 *           (C) 2023 The LibreMobileOS Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.internal.util;

import android.app.ActivityTaskManager;
import android.app.Application;
import android.app.TaskStackListener;
import android.content.ComponentName;
import android.content.Context;
import android.content.res.Resources;
import android.os.Build;
import android.os.Binder;
import android.os.Process;
import android.os.SystemProperties;
import android.text.TextUtils;
import android.util.Log;

import com.android.internal.R;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

public class PropImitationHooks {

    private static final String TAG = "PropImitationHooks";
    private static final boolean DEBUG = SystemProperties.getBoolean("debug.pihooks.log", false);

    private static final String PACKAGE_ARCORE = "com.google.ar.core";
    private static final String PACKAGE_EMOJIWALLPAPER = "com.google.android.apps.emojiwallpaper";

    private static final String PACKAGE_FINSKY = "com.android.vending";
    private static final String PACKAGE_GMS = "com.google.android.gms";
    private static final String PACKAGE_LIVEWALLPAPER = "com.google.pixel.livewallpaper";

    private static final String PACKAGE_PIXELTHEMES = "com.google.android.apps.customization.pixel";
    private static final String PACKAGE_WALLPAPER = "com.google.android.apps.wallpaper";
    private static final String PACKAGE_WALLPAPEREFFECTS = "com.google.android.wallpaper.effects";

    private static final String PACKAGE_GPHOTOS = "com.google.android.apps.photos";
    private static final String PACKAGE_NETFLIX = "com.netflix.mediaclient";
    private static final String PACKAGE_VELVET = "com.google.android.googlequicksearchbox";

// Gaming Packages
    private static final String G_ONE = "com.pubg.imobile";
    private static final String G_TWO = "com.pubg.krmobile";
    private static final String G_THR = "com.rekoo.pubgm";
    private static final String G_FOU = "com.tencent.ig";
    private static final String G_FIV = "com.tencent.tmgp.pubgmhd";
    private static final String G_SIX = "com.vng.pubgmobile";

    private static final String PROCESS_GMS_PERSISTENT = PACKAGE_GMS + ".persistent";
    private static final String PROCESS_GMS_UNSTABLE = PACKAGE_GMS + ".unstable";

    private static final String PROP_SECURITY_PATCH = "persist.sys.pihooks.security_patch";
    private static final String PROP_FIRST_API_LEVEL = "persist.sys.pihooks.first_api_level";

    private static final ComponentName GMS_ADD_ACCOUNT_ACTIVITY = ComponentName.unflattenFromString(
            "com.google.android.gms/.auth.uiflows.minutemaid.MinuteMaidActivity");

    private static final String FEATURE_NEXUS_PRELOAD =
            "com.google.android.apps.photos.NEXUS_PRELOAD";

    private static final Map<String, String> sPixelSixProps = Map.of(
        "PRODUCT", "raven",
        "DEVICE", "raven",
        "HARDWARE", "raven",
        "MANUFACTURER", "Google",
        "BRAND", "google",
        "MODEL", "Pixel 6 Pro",
        "ID", "AP1A.240505.004",
        "FINGERPRINT", "google/raven/raven:14/AP1A.240505.004/11583682:user/release-keys"
    );

    private static final Map<String, String> sPixelOneProps = Map.of(
        "PRODUCT", "sailfish",
        "DEVICE", "sailfish",
        "HARDWARE", "sailfish",
        "MANUFACTURER", "Google",
        "BRAND", "google",
        "MODEL", "Pixel",
        "ID", "QP1A.191005.007.A3",
        "FINGERPRINT", "google/sailfish/sailfish:10/QP1A.191005.007.A3/5972272:user/release-keys"
    );

    private static final Map<String, String> sOneplusEightProProps = Map.of(
        "MANUFACTURER", "OnePlus",
        "MODEL", "IN2020"
    );

    private static final Set<String> sPixelFeatures = Set.of(
        "PIXEL_2017_PRELOAD",
        "PIXEL_2018_PRELOAD",
        "PIXEL_2019_MIDYEAR_PRELOAD",
        "PIXEL_2019_PRELOAD",
        "PIXEL_2020_EXPERIENCE",
        "PIXEL_2020_MIDYEAR_EXPERIENCE",
        "PIXEL_2021_EXPERIENCE",
        "PIXEL_2021_MIDYEAR_EXPERIENCE"
    );

    private static volatile String[] sCertifiedProps;
    private static volatile String sStockFp, sNetflixModel;
    private static volatile boolean sSpoofGapps;

    private static volatile String sProcessName;
    private static volatile boolean sIsGms, sIsFinsky, sIsPhotos;

    public static void setProps(Context context) {
        final String packageName = context.getPackageName();
        final String processName = Application.getProcessName();

        if (TextUtils.isEmpty(packageName) || TextUtils.isEmpty(processName)) {
            Log.e(TAG, "Null package or process name");
            return;
        }

        final Resources res = context.getResources();
        if (res == null) {
            Log.e(TAG, "Null resources");
            return;
        }

        sCertifiedProps = res.getStringArray(R.array.config_certifiedBuildProperties);
        sStockFp = res.getString(R.string.config_stockFingerprint);
        sNetflixModel = res.getString(R.string.config_netflixSpoofModel);
        sSpoofGapps = res.getBoolean(R.bool.config_spoofGoogleApps);

        sProcessName = processName;
        sIsGms = packageName.equals(PACKAGE_GMS) && processName.equals(PROCESS_GMS_UNSTABLE);
        sIsFinsky = packageName.equals(PACKAGE_FINSKY);
        sIsPhotos = sSpoofGapps && packageName.equals(PACKAGE_GPHOTOS);

        if (sIsGms) {
            setCertifiedPropsForGms();
        } else if (!sStockFp.isEmpty() && packageName.equals(PACKAGE_ARCORE)) {
            dlog("Setting stock fingerprint for: " + packageName);
            setPropValue("FINGERPRINT", sStockFp);
        } else if (sSpoofGapps && (packageName.equals(PACKAGE_VELVET)
		|| packageName.equals(PACKAGE_EMOJIWALLPAPER)
		|| packageName.equals(PACKAGE_LIVEWALLPAPER)
                || packageName.equals(PACKAGE_PIXELTHEMES)
		|| packageName.equals(PACKAGE_WALLPAPER)
        || packageName.equals(PACKAGE_WALLPAPEREFFECTS)
                || (packageName.equals(PACKAGE_GMS)
		&& processName.equals(PROCESS_GMS_PERSISTENT)))) {
            dlog("Spoofing Pixel 6 Pro for: " + packageName + " process: " + processName);
            sPixelSixProps.forEach(PropImitationHooks::setPropValue);
        } else if (packageName.equals(G_ONE) || packageName.equals(G_TWO) || packageName.equals(G_THR) || packageName.equals(G_FOU) || packageName.equals(G_FIV) || packageName.equals(G_SIX)) {
            sOneplusEightProProps.forEach(PropImitationHooks::setPropValue);
        } else if (sIsPhotos) {
            dlog("Spoofing Pixel 1 for Google Photos");
            sPixelOneProps.forEach((PropImitationHooks::setPropValue));
        } else if (!sNetflixModel.isEmpty() && packageName.equals(PACKAGE_NETFLIX)) {
            dlog("Setting model to " + sNetflixModel + " for Netflix");
            setPropValue("MODEL", sNetflixModel);
        }
    }

    private static void setPropValue(String key, String value) {
        try {
            dlog("Setting prop " + key + " to " + value.toString());
            Class clazz = Build.class;
            if (key.startsWith("VERSION.")) {
                clazz = Build.VERSION.class;
                key = key.substring(8);
            }
            Field field = clazz.getDeclaredField(key);
            field.setAccessible(true);
            // Cast the value to int if it's an integer field, otherwise string.
            field.set(null, field.getType().equals(Integer.TYPE) ? Integer.parseInt(value) : value);
            field.setAccessible(false);
        } catch (Exception e) {
            Log.e(TAG, "Failed to set prop " + key, e);
        }
    }

    private static void setCertifiedPropsForGms() {
        if (sCertifiedProps.length == 0) {
            dlog("Certified props are not set");
            return;
        }
        final boolean was = isGmsAddAccountActivityOnTop();
        final TaskStackListener taskStackListener = new TaskStackListener() {
            @Override
            public void onTaskStackChanged() {
                final boolean is = isGmsAddAccountActivityOnTop();
                if (is ^ was) {
                    dlog("GmsAddAccountActivityOnTop is:" + is + " was:" + was +
                            ", killing myself!"); // process will restart automatically later
                    Process.killProcess(Process.myPid());
                }
            }
        };
        if (!was) {
            dlog("Spoofing build for GMS");
            setCertifiedProps();
        } else {
            dlog("Skip spoofing build for GMS, because GmsAddAccountActivityOnTop");
        }
        try {
            ActivityTaskManager.getService().registerTaskStackListener(taskStackListener);
        } catch (Exception e) {
            Log.e(TAG, "Failed to register task stack listener!", e);
        }
    }

    private static void setCertifiedProps() {
        for (String entry : sCertifiedProps) {
            // Each entry must be of the format FIELD:value
            final String[] fieldAndProp = entry.split(":", 2);
            if (fieldAndProp.length != 2) {
                Log.e(TAG, "Invalid entry in certified props: " + entry);
                continue;
            }
            setPropValue(fieldAndProp[0], fieldAndProp[1]);
        }
        setSystemProperty(PROP_SECURITY_PATCH, Build.VERSION.SECURITY_PATCH);
        setSystemProperty(PROP_FIRST_API_LEVEL,
                Integer.toString(Build.VERSION.DEVICE_INITIAL_SDK_INT));
    }

    private static void setSystemProperty(String name, String value) {
        try {
            SystemProperties.set(name, value);
            dlog("Set system prop " + name + "=" + value);
        } catch (Exception e) {
            Log.e(TAG, "Failed to set system prop " + name + "=" + value, e);
        }
    }

    private static boolean isGmsAddAccountActivityOnTop() {
        try {
            final ActivityTaskManager.RootTaskInfo focusedTask =
                    ActivityTaskManager.getService().getFocusedRootTaskInfo();
            return focusedTask != null && focusedTask.topActivity != null
                    && focusedTask.topActivity.equals(GMS_ADD_ACCOUNT_ACTIVITY);
        } catch (Exception e) {
            Log.e(TAG, "Unable to get top activity!", e);
        }
        return false;
    }

    public static boolean shouldBypassTaskPermission(Context context) {
        // GMS doesn't have MANAGE_ACTIVITY_TASKS permission
        final int callingUid = Binder.getCallingUid();
        final int gmsUid;
        try {
            gmsUid = context.getPackageManager().getApplicationInfo(PACKAGE_GMS, 0).uid;
            dlog("shouldBypassTaskPermission: gmsUid:" + gmsUid + " callingUid:" + callingUid);
        } catch (Exception e) {
            Log.e(TAG, "shouldBypassTaskPermission: unable to get gms uid", e);
            return false;
        }
        return gmsUid == callingUid;
    }

    private static boolean isCallerSafetyNet() {
        return sIsGms && Arrays.stream(Thread.currentThread().getStackTrace())
                .anyMatch(elem -> elem.getClassName().contains("DroidGuard"));
    }

    public static void onEngineGetCertificateChain() {
        // Check stack for SafetyNet or Play Integrity
        if (isCallerSafetyNet() || sIsFinsky) {
            dlog("Blocked key attestation sIsGms=" + sIsGms + " sIsFinsky=" + sIsFinsky);
            throw new UnsupportedOperationException();
        }
    }

    public static boolean hasSystemFeature(String name, boolean has) {
        if (sIsPhotos) {
            if (has && sPixelFeatures.stream().anyMatch(name::contains)) {
                dlog("Blocked system feature " + name + " for Google Photos");
                has = false;
            } else if (!has && name.equalsIgnoreCase(FEATURE_NEXUS_PRELOAD)) {
                dlog("Enabled system feature " + name + " for Google Photos");
                has = true;
            }
        }
        return has;
    }

    public static void dlog(String msg) {
        if (DEBUG) Log.d(TAG, "[" + sProcessName + "] " + msg);
    }
}
