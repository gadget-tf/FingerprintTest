package com.x0.gadget_tf.fingerprinttest.state;

import android.content.Context;

public interface TestState {
    public static final int NONE = 0;
    public static final int SUCCESS = 1;
    public static final int FAIL = 2;
    public static final int COMP = 3;

    public interface OnCallbackListener {
        void onComplete(int result);
    }

    int start();
    void setCallbackListener(OnCallbackListener listener);
    int getNowState();
    String getMessage();
}
