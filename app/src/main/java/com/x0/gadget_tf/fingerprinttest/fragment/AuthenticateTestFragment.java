package com.x0.gadget_tf.fingerprinttest.fragment;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.hardware.fingerprint.FingerprintManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.v4.app.Fragment;
import android.util.Printer;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Toast;

import com.x0.gadget_tf.fingerprinttest.ConfirmDialog;
import com.x0.gadget_tf.fingerprinttest.MyApplication;
import com.x0.gadget_tf.fingerprinttest.R;

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

/**
 * A simple {@link Fragment} subclass.
 * Activities that contain this fragment must implement the
 * {@link AuthenticateTestFragment.OnFragmentInteractionListener} interface
 * to handle interaction events.
 * Use the {@link AuthenticateTestFragment#newInstance} factory method to
 * create an instance of this fragment.
 */
public class AuthenticateTestFragment extends Fragment {
    // TODO: Rename parameter arguments, choose names that match
    // the fragment initialization parameters, e.g. ARG_ITEM_NUMBER
    private static final String ARG_PARAM1 = "param1";
    private static final String ARG_PARAM2 = "param2";
    private static final String KEY_NAME = "test_key";

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
            mDialog.dismiss();
            mSelectedNumber++;
            onActivityResult(ConfirmDialog.REQUEST_CONFIRM, Activity.RESULT_OK, null);
        }

        @Override
        public void onAuthenticationFailed() {
            super.onAuthenticationFailed();
            mDialog.dismiss();
            mSelectedNumber++;
            onActivityResult(ConfirmDialog.REQUEST_CONFIRM, Activity.RESULT_OK, null);
        }
    };
    private CancellationSignal mCancelSignal;

    // TODO: Rename and change types of parameters
    private String mParam1;
    private String mParam2;
    private FingerprintManager mFingerprintManager;
    private ConfirmDialog mDialog;
    private int mSelectedNumber;
    private KeyStore mKeyStore;
    private KeyGenerator mKeyGenerator;
    private Cipher mCipher;
    private FingerprintManager.CryptoObject mCryptoObject;

    private OnFragmentInteractionListener mListener;

    public AuthenticateTestFragment() {
        // Required empty public constructor
    }

    /**
     * Use this factory method to create a new instance of
     * this fragment using the provided parameters.
     *
     * @param param1 Parameter 1.
     * @param param2 Parameter 2.
     * @return A new instance of fragment AuthenticateTestFragment.
     */
    // TODO: Rename and change types and number of parameters
    public static AuthenticateTestFragment newInstance(String param1, String param2) {
        AuthenticateTestFragment fragment = new AuthenticateTestFragment();
        Bundle args = new Bundle();
        args.putString(ARG_PARAM1, param1);
        args.putString(ARG_PARAM2, param2);
        fragment.setArguments(args);
        return fragment;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getArguments() != null) {
            mParam1 = getArguments().getString(ARG_PARAM1);
            mParam2 = getArguments().getString(ARG_PARAM2);
        }

        mFingerprintManager = MyApplication.getFingerprintManager();//(FingerprintManager)getActivity().getSystemService(Context.FINGERPRINT_SERVICE);

        generateKey();
        if (cipherInit()) {
            mCryptoObject = new FingerprintManager.CryptoObject(mCipher);
        }

        mSelectedNumber = 0;
        mDialog =
                ConfirmDialog.newInstance(this, ConfirmDialog.REQUEST_OKCANCEL, "テストを開始します。");
        mDialog.show(getFragmentManager(), "dialog");
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == ConfirmDialog.REQUEST_OKCANCEL) {
            if (resultCode == Activity.RESULT_OK) {
                onActivityResult(ConfirmDialog.REQUEST_CONFIRM, Activity.RESULT_OK, null);
            } else if (resultCode == Activity.RESULT_CANCELED) {
                if (mListener != null) {
                    mListener.onFragmentInteraction();
                }
            }
        } else if (requestCode == ConfirmDialog.REQUEST_CONFIRM) {
            
            if (mSelectedNumber == 0) {
                mFingerprintManager.authenticate(null, mCancelSignal, 0, mAuthenticationCallback, null);
                mDialog =
                        ConfirmDialog.newInstance(this, ConfirmDialog.REQUEST_CONFIRM, getString(R.string.authenticate_1));
                mDialog.show(getFragmentManager(), "dialog");
            } else if (mSelectedNumber == 1) {
                mFingerprintManager.authenticate(null, null, 0, mAuthenticationCallback, null);
                mDialog =
                        ConfirmDialog.newInstance(this, ConfirmDialog.REQUEST_CONFIRM, getString(R.string.authenticate_2));
                mDialog.show(getFragmentManager(), "dialog");
            } else if (mSelectedNumber == 2) {
                Looper looper = Looper.getMainLooper();
                looper.setMessageLogging(new Printer() {
                    @Override
                    public void println(final String s) {
                    }
                });
                mFingerprintManager.authenticate(null, mCancelSignal, 0, mAuthenticationCallback, new Handler(looper));
                mDialog =
                        ConfirmDialog.newInstance(this, ConfirmDialog.REQUEST_CONFIRM, getString(R.string.authenticate_3));
                mDialog.show(getFragmentManager(), "dialog");
            } else if (mSelectedNumber == 3) {
                mFingerprintManager.authenticate(mCryptoObject, mCancelSignal, 0, mAuthenticationCallback, null);
                mDialog =
                        ConfirmDialog.newInstance(this, ConfirmDialog.REQUEST_CONFIRM, getString(R.string.authenticate_4));
                mDialog.show(getFragmentManager(), "dialog");
            } else if (mSelectedNumber == 4) {
                int flag = -1;
                try {
                    mFingerprintManager.authenticate(mCryptoObject, mCancelSignal, 0, null, null);
                    flag = 0;
                } catch (IllegalArgumentException e) {
                    flag = 1;
                } catch (Exception e) {
                    flag = 2;
                }
                mDialog =
                        ConfirmDialog.newInstance(this, ConfirmDialog.REQUEST_TIMER, getString(R.string.authenticate_5), flag);
                mDialog.show(getFragmentManager(), "dialog");
            }
        } else if (requestCode == ConfirmDialog.REQUEST_TIMER) {
            mDialog.dismiss();
            int flag = data.getIntExtra("flag", -1);
            if (flag == 1) {
                mDialog =
                        ConfirmDialog.newInstance(this, ConfirmDialog.REQUEST_CONFIRM, "試験終了");
                mDialog.show(getFragmentManager(), "dialog");
            }
            //if (mListener != null) {
            //    mListener.onFragmentInteraction();
            //}
        }
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        // Inflate the layout for this fragment
        return inflater.inflate(R.layout.fragment_authenticate_test, container, false);
    }

    @Override
    public void onAttach(Context context) {
        super.onAttach(context);
        if (context instanceof OnFragmentInteractionListener) {
            mListener = (OnFragmentInteractionListener) context;
        } else {
            throw new RuntimeException(context.toString()
                    + " must implement OnFragmentInteractionListener");
        }
    }

    @Override
    public void onDetach() {
        super.onDetach();
        mListener = null;
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

    /**
     * This interface must be implemented by activities that contain this
     * fragment to allow an interaction in this fragment to be communicated
     * to the activity and potentially other fragments contained in that
     * activity.
     * <p>
     * See the Android Training lesson <a href=
     * "http://developer.android.com/training/basics/fragments/communicating.html"
     * >Communicating with Other Fragments</a> for more information.
     */
    public interface OnFragmentInteractionListener {
        // TODO: Update argument type and name
        void onFragmentInteraction();
    }
}
