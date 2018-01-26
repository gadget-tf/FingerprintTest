package com.x0.gadget_tf.fingerprinttest;

import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Toast;

import com.x0.gadget_tf.fingerprinttest.fragment.AuthenticateTestFragment;
import com.x0.gadget_tf.fingerprinttest.fragment.MenuFragment;

public class MainActivity extends AppCompatActivity
        implements MenuFragment.OnMenuSelectedListener, AuthenticateTestFragment.OnFragmentInteractionListener {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        getSupportFragmentManager().beginTransaction().
                replace(R.id.mainContainer, new MenuFragment()).commit();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    @Override
    public void onFragmentInteraction() {
        getSupportFragmentManager().beginTransaction().
                replace(R.id.mainContainer, new MenuFragment()).commit();
        Toast.makeText(this, "return", Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onSelectedMenu(int id) {
        if (id == R.id.button1) {
            getSupportFragmentManager().beginTransaction().
                    replace(R.id.mainContainer, new AuthenticateTestFragment()).addToBackStack(null).commit();
        }
    }
}
