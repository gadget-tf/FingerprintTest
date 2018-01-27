package com.x0.gadget_tf.fingerprinttest;

import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.View;
import android.widget.Toast;

import com.x0.gadget_tf.fingerprinttest.fragment.AuthenticateTestFragment;

public class TestActivity extends AppCompatActivity implements AuthenticateTestFragment.OnFragmentInteractionListener  {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_test);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        getSupportFragmentManager().beginTransaction().
                replace(R.id.testContainer, new AuthenticateTestFragment()).commit();
    }

    @Override
    public void onFragmentInteraction() {
        Toast.makeText(this, "return", Toast.LENGTH_SHORT).show();
        finish();
    }
}
