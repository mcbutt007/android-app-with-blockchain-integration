package com.example.virusdetection.ui.notifications;


import android.app.Activity;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import com.example.virusdetection.databinding.FragmentNotificationsBinding;
import com.example.virusdetection.utils.Client;

import java.security.KeyPair;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class NotificationsFragment extends Fragment {

    private static final ExecutorService executor = Executors.newCachedThreadPool();
    private FragmentNotificationsBinding binding;

    public View onCreateView(@NonNull LayoutInflater inflater,
                             ViewGroup container, Bundle savedInstanceState) {
        NotificationsViewModel notificationsViewModel =
                new ViewModelProvider(this).get(NotificationsViewModel.class);

        binding = FragmentNotificationsBinding.inflate(inflater, container, false);
        View root = binding.getRoot();


        final TextView textView = binding.textNotifications;
        final TextView address = binding.address;
        final TextView send_value = binding.value;
        Button send_btn = binding.sendBtn;
        Activity activity = this.getActivity();

        send_btn.setOnClickListener(v -> executor.execute(() -> {
            try {
                String receiverPublicKey = address.getText().toString();
                long value = Long.parseLong(send_value.getText().toString());
                System.out.println( "Sending " + value + " to " + receiverPublicKey);
                System.out.println(Client.num);
                if (Client.num < value) return;
                Client.num -= value;
                assert activity != null;
                KeyPair key = Client.getKey(activity);
                Boolean b = Client.transfer(key, receiverPublicKey, value);
                System.out.println(b);
                System.out.println("after transfer");
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }));

        notificationsViewModel.getText().observe(getViewLifecycleOwner(), textView::setText);
        return root;
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        binding = null;
    }
}