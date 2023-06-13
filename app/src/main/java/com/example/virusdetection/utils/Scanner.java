package com.example.virusdetection.utils;

import android.app.Activity;
import android.widget.TextView;

import com.example.virusdetection.ui.home.Job;
import com.example.virusdetection.ui.home.JobBigInt;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Scanner implements  Runnable{
    private static ExecutorService executor = Executors.newCachedThreadPool();
    private static Scanner scanner;
    private static boolean activated = false;

    private Activity activity;
    private TextView keyView, valueView;

    private KeyPair keyPair;

    private Scanner(Activity activity, TextView keyView, TextView valueView) throws Exception {
        this.activity = activity;
        this.keyView = keyView;
        this.valueView = valueView;
        this.keyPair = Client.getKey(this.activity);
    }

    @Override
    public void run() {
        try {
            SecureRandom rand = new SecureRandom();

            while(activated) {
                try{
                    Thread.currentThread().wait(1000);
                }
                catch (Exception ignored){}
                int rand_int = rand.nextInt(10000);
                //System.out.println(rand_int);
                if (rand_int > 1907) continue;

                int virusRandom = rand.nextInt();
                Virus virus = new Virus();
                virus.publicKey = CustomECKeySpec.getPublicKeySpec(keyPair);
                virus.virusSignature = String.valueOf(virusRandom);

                Boolean b = Client.addVirus(keyPair, virus);

                // if (!b) return;
                //Client.num += 1;
                int coins = Client.fetch(keyPair, false);
                // write coins to UI in UI thread
                activity.runOnUiThread(new Job(valueView, coins));
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
    public static Scanner getScanner(Activity activity, TextView key, TextView value) throws Exception {
        if (scanner == null){
            scanner = new Scanner(activity, key, value);
            return scanner;
        }
        return scanner;
    }

    public static synchronized void activate(Activity activity, TextView key, TextView value) throws Exception {
        activated = !activated;
        if (activated){
            executor.execute(Scanner.getScanner(activity, key, value));
        }
    }
}
