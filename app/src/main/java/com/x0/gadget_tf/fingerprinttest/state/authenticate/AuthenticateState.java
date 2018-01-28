package com.x0.gadget_tf.fingerprinttest.state.authenticate;

import android.app.Activity;
import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Printer;

import com.x0.gadget_tf.fingerprinttest.ConfirmDialog;
import com.x0.gadget_tf.fingerprinttest.MyApplication;
import com.x0.gadget_tf.fingerprinttest.state.TestState;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class AuthenticateState implements TestState {
    private static final String KEY_NAME = "test_key";

    private static int mNowState = 0;
    private KeyStore mKeyStore;
    private KeyGenerator mKeyGenerator;
    private Cipher mCipher;
    private FingerprintManager.CryptoObject mCryptoObject;

    private FingerprintManager.AuthenticationCallback mAuthenticationCallback = new FingerprintManager.AuthenticationCallback() {
        @Override
        public void onAuthenticationError(int errorCode, CharSequence errString) {
            super.onAuthenticationError(errorCode, errString);
        }

        @Override
        public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
            super.onAuthenticationHelp(helpCode, helpString);
        }

        @Override
        public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
            super.onAuthenticationSucceeded(result);
            if (mListener != null) {
                mListener.onComplete(TestState.SUCCESS);
            }
        }

        @Override
        public void onAuthenticationFailed() {
            super.onAuthenticationFailed();
            if (mListener != null) {
                mListener.onComplete(TestState.SUCCESS);
            }
        }
    };
    private CancellationSignal mCancelSignal;
    private TestState.OnCallbackListener mListener;

    @Override
    public int start(Context context) {
        FingerprintManager fingerprintManager = MyApplication.getFingerprintManager();
        if (mNowState == 0) {
            fingerprintManager.authenticate(null, mCancelSignal, 0, mAuthenticationCallback, null);
        } else if (mNowState == 1) {
            fingerprintManager.authenticate(null, null, 0, mAuthenticationCallback, null);
        } else if (mNowState == 2) {
            Looper looper = Looper.getMainLooper();
            looper.setMessageLogging(new Printer() {
                @Override
                public void println(final String s) {
                }
            });
            fingerprintManager.authenticate(null, mCancelSignal, 0, mAuthenticationCallback, new Handler(looper));
        } else if (mNowState == 3) {
            fingerprintManager.authenticate(mCryptoObject, mCancelSignal, 0, mAuthenticationCallback, null);
        } else if (mNowState == 4) {
            int flag = TestState.NONE;
            try {
                fingerprintManager.authenticate(mCryptoObject, mCancelSignal, 0, null, null);
                flag = TestState.FAIL;
            } catch (IllegalArgumentException e) {
                flag = TestState.SUCCESS;
            } catch (Exception e) {
                flag = TestState.FAIL;
            }
            if (mListener != null) {
                mListener.onComplete(flag);
            }
        } else if (mNowState == 5) {
            if (mListener != null) {
                mListener.onComplete(TestState.COMP);
            }
        }

        return 0;
    }

    @Override
    public void setCallbackListener(TestState.OnCallbackListener listener) {
        mListener = listener;
    }

    @Override
    public int getNowState() {
        return mNowState;
    }

    private void generateKey() {
        try {
            mKeyStore = KeyStore.getInstance("AndroidKeyStore");
        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            mKeyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException("Failed to get KeyGenerator instance", e);
        }

        try {
            mKeyStore.load(null);
            mKeyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT |
                            KeyProperties.PURPOSE_DECRYPT).setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7).build());
            mKeyGenerator.generateKey();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException |
                CertificateException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    private boolean cipherInit() {
        try {
            mCipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get Cipher", e);
        }

        try {
            mKeyStore.load(null);
            SecretKey key = (SecretKey)mKeyStore.getKey(KEY_NAME, null);
            mCipher.init(Cipher.ENCRYPT_MODE, key);
            return true;
        } catch (KeyPermanentlyInvalidatedException e) {
            return false;
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException |
                UnrecoverableKeyException | InvalidKeyException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        }
    }
}
