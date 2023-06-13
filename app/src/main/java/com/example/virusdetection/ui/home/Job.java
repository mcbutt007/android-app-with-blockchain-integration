package com.example.virusdetection.ui.home;

import android.widget.TextView;

public class Job implements Runnable {
    TextView valueTextView;
    int value;

    public Job(TextView textView, int value){
        this.valueTextView = textView;
        this.value = value;
    }

    @Override
    public void run() {
        // update coins
        valueTextView.setText(String.valueOf(value));
    }
}
