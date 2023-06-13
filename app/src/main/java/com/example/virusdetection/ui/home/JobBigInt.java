package com.example.virusdetection.ui.home;

import java.math.BigInteger;

import android.widget.TextView;

public class JobBigInt implements Runnable {
    TextView valueTextView;
    BigInteger value;

    JobBigInt(TextView textView, BigInteger value){
        this.valueTextView = textView;
        this.value = value;
    }

    @Override
    public void run() {
        // update coins
        valueTextView.setText(value.toString(16));
    }
}
