package com.android.internal.util;

import android.app.Application;
import android.content.Context;
import android.os.Build;
import android.text.TextUtils;
import android.util.Log;

import java.lang.reflect.Field;
import java.util.Map;

/**
 * @hide
 */
public final class Utils {
    private static final String TAG = Utils.class.getSimpleName();

    private static final Map<String, String> map = Map.of(
            "ID", "AP31.240617.015",
            "BRAND", "google",
            "DEVICE", "akita",
            "FINGERPRINT", "google/akita_beta/akita:15/AP31.240617.015/12207491:user/release-keys",
            "MANUFACTURER", "Google",
            "MODEL", "Pixel 8a",
            "PRODUCT", "akita_beta",
            "SECURITY_PATCH", "2024-08-05"
    );

    private static Field getBuildField(String name) {
        Field field;

        try {
            field = Build.class.getDeclaredField(name);
        } catch (NoSuchFieldException e) {
            try {
                field = Build.VERSION.class.getDeclaredField(name);
            } catch (NoSuchFieldException ex) {
                return null;
            }
        }

        return field;
    }

    public static void onNewApplication(Context context) {
        if (context == null)
            return;

        final String packageName = context.getPackageName();

        if (TextUtils.isEmpty(packageName) || !"com.google.android.gms".equals(packageName))
            return;

        final String process = Application.getProcessName();

        if (TextUtils.isEmpty(process) || !"com.google.android.gms.unstable".equals(process))
            return;

        map.forEach((fieldName, value) -> {
            Field field = getBuildField(fieldName);
            if (field == null) return;
            field.setAccessible(true);
            try {
                field.set(null, value);
            } catch (IllegalAccessException e) {
                Log.e(TAG, Log.getStackTraceString(e));
            }
            field.setAccessible(false);
        });
    }
}
