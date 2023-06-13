package com.example.virusdetection.ui.home;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import com.example.virusdetection.R;
import com.example.virusdetection.databinding.FragmentHomeBinding;
import com.example.virusdetection.utils.Client;
import com.example.virusdetection.utils.CustomECKeySpec;
import com.example.virusdetection.utils.Tools;
import com.example.virusdetection.utils.Tools.*;
import com.example.virusdetection.utils.Virus;
import com.google.gson.Gson;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class HomeFragment extends Fragment {
    private static ExecutorService executor = Executors.newCachedThreadPool();

    private FragmentHomeBinding binding;

    private int value = Client.num;
    public View onCreateView(@NonNull LayoutInflater inflater,
                             ViewGroup container, Bundle savedInstanceState) {
        HomeViewModel homeViewModel =
                new ViewModelProvider(this).get(HomeViewModel.class);

        binding = FragmentHomeBinding.inflate(inflater, container, false);
        View root = binding.getRoot();

        Button addButton = binding.scanButton;
        final TextView valueTextView = binding.virusPoint;
        final TextView valueKey = binding.key;
        Activity activity = this.getActivity();

        executor.execute(new Runnable() {
            @Override
            public void run() {

                KeyPair key = null;
                try {
                    key = Client.getKey(activity);

                    int coins = Client.fetch(key, false);
                    // write address to UI in UI thread
                    activity.runOnUiThread(new JobBigInt(valueKey, new BigInteger(key.getPublic().getEncoded())));
                    // write coins to UI in UI thread
                    activity.runOnUiThread(new Job(valueTextView, coins));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }

        });

        addButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                executor.execute(new Runnable() {
                    @Override
                    public void run() {
                        SecureRandom rand = new SecureRandom();
                        int rand_int = rand.nextInt(10000);
                        System.out.println(rand_int);
                        if (rand_int > 1907) return;

                        int virusRandom = rand.nextInt();

                        KeyPair key = null;
                        try {
                            key = Client.getKey(activity);

                            Virus virus = new Virus();
                            virus.publicKey = CustomECKeySpec.getPublicKeySpec(key);
                            virus.virusSignature = String.valueOf(virusRandom);

                            Boolean b = Client.addVirus(key, virus);

                            // if (!b) return;
                            //Client.num += 1;
                            int coins = Client.fetch(key, false);
                            // write coins to UI in UI thread
                            activity.runOnUiThread(new Job(valueTextView, coins));
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }
        
                });
            }
        });

        final TextView textView = binding.textHome;
        homeViewModel.getText().observe(getViewLifecycleOwner(), textView::setText);
        return root;
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        binding = null;
    }
}