package com.x0.gadget_tf.fingerprinttest;

import android.app.Application;
import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;

public class MyApplication extends Application {
    private static FingerprintManager fingerprintManager;

    @Override
    public void onCreate() {
        super.onCreate();

        fingerprintManager = (FingerprintManager)getSystemService(Context.FINGERPRINT_SERVICE);
    }

    public static FingerprintManager getFingerprintManager() {
        return fingerprintManager;
    }
}
