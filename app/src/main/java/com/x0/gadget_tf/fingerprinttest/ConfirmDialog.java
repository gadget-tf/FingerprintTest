package com.x0.gadget_tf.fingerprinttest;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.support.v4.app.DialogFragment;
import android.support.v4.app.Fragment;


public class ConfirmDialog extends DialogFragment {
    private static final String ARG_MSG = "msg";
    private static final String ARG_FLAG = "flag";

    public static final int REQUEST_OKCANCEL = 1;
    public static final int REQUEST_CONFIRM = 2;
    public static final int REQUEST_TIMER = 3;
    public static final int REQUEST_OK = 4;

    public static ConfirmDialog newInstance(Fragment target, int requestCode, String message) {
        ConfirmDialog dialog = new ConfirmDialog();
        Bundle args = new Bundle();
        args.putString(ARG_MSG, message);

        dialog.setArguments(args);
        dialog.setTargetFragment(target, requestCode);

        return dialog;
    }

    public static ConfirmDialog newInstance(Fragment target, int requestCode, String message, int flag) {
        ConfirmDialog dialog = new ConfirmDialog();
        Bundle args = new Bundle();
        args.putString(ARG_MSG, message);
        args.putInt(ARG_FLAG, flag);

        dialog.setArguments(args);
        dialog.setTargetFragment(target, requestCode);

        return dialog;
    }

    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
        final String message = getArguments().getString(ARG_MSG);
        final int requestCode = getTargetRequestCode();
        final Fragment targetFragment = getTargetFragment();

        AlertDialog.Builder builder = new AlertDialog.Builder(getActivity());
        builder.setMessage(message);
        if (requestCode == REQUEST_OKCANCEL) {
            builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialogInterface, int i) {
                    targetFragment.onActivityResult(requestCode, Activity.RESULT_OK, null);
                }
            }).setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialogInterface, int i) {
                    targetFragment.onActivityResult(requestCode, Activity.RESULT_CANCELED, null);
                }
            });
        } else if (requestCode == REQUEST_CONFIRM) {
        } else if (requestCode == REQUEST_TIMER) {
            new Handler().postDelayed(new Runnable() {
                @Override
                public void run() {
                    int flag = getArguments().getInt(ARG_FLAG);
                    Intent intent = new Intent();
                    intent.putExtra(ARG_FLAG, flag);
                    targetFragment.onActivityResult(requestCode, Activity.RESULT_OK, intent);
                }
            }, 1000);
        } else if (requestCode == REQUEST_OK) {
            builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialogInterface, int i) {
                    targetFragment.onActivityResult(requestCode, Activity.RESULT_OK, null);
                }
            });
        }

        return builder.create();
    }
}
