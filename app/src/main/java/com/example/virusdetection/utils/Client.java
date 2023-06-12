package com.example.virusdetection.utils;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import com.example.virusdetection.R;
import com.google.gson.Gson;

import javax.net.SocketFactory;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Client {
    public static final String SERVER_ADDRESS = "0.tcp.ap.ngrok.io";
    public static final int SERVER_PORT = 12592;
    
    public static SocketFactory sf = (SocketFactory)SocketFactory.getDefault();
    public static Socket client;
    public static DataOutputStream dos;
    public static DataInputStream dis;

    public static int num = 0;

    public static KeyPair getKey(Activity context) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // get key
        SharedPreferences sharedPref = context.getPreferences(Context.MODE_PRIVATE);
        String json = sharedPref.getString(context.getString(R.string.saved_key), "");
        Gson gson = new Gson();
        if (json.equals("")){
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
            keygen.initialize(ecSpec);
            KeyPair keyPair = keygen.generateKeyPair();
            //test.createNewAddress(keyPair);
            String keyPairString = gson.toJson(new CustomECKeySpec(keyPair), CustomECKeySpec.class);
            SharedPreferences.Editor editor = sharedPref.edit();
            editor.putString(context.getString(R.string.saved_key), keyPairString);
            editor.apply();
            return keyPair;
        }
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        String saved_key = "";
        CustomECKeySpec customECKeySpec = gson.fromJson(saved_key, CustomECKeySpec.class);
        PrivateKey privateKey = keyFactory.generatePrivate(customECKeySpec.getPrivateKeySpec());
        PublicKey publicKey =  keyFactory.generatePublic(customECKeySpec.getPublicKeySpec());
        KeyPair keyPair = new KeyPair(publicKey, privateKey);
        return keyPair;
    }

    static Boolean createNewAddress(KeyPair ecKeyPair) throws UnknownHostException, IOException, NoSuchAlgorithmException{
        try(
            Socket client = (Socket) sf.createSocket(SERVER_ADDRESS, SERVER_PORT);
            DataInputStream dis = new DataInputStream(client.getInputStream());
            DataOutputStream dos = new DataOutputStream(client.getOutputStream());){

            Gson gson = new Gson();
            SignedObject so = new SignedObject();
            
            so.objectString = gson.toJson(CustomECKeySpec.getPublicKeySpec(keyPair), CustomECKeySpec.class);
    
            // Print the private key.
            System.out.println("private: " + (new BigInteger(keyPair.getPrivate().getEncoded())).toString(16));
            // Print the public key.
            System.out.println("pub: " + (new BigInteger(keyPair.getPublic().getEncoded())).toString(16));
            byte[] signature = EthersUtils.signData(so.objectString.getBytes(StandardCharsets.US_ASCII), keyPair.getPrivate());
    
            so.signature = signature;
    
            String objectString = gson.toJson(so, SignedObject.class);
    
            System.out.println(objectString);

            dos.write(Tools.combine("0200".getBytes(StandardCharsets.UTF_16LE), Tools.data_with_ASCII_byte(objectString).getBytes(StandardCharsets.US_ASCII)));
            String code = Tools.receive_unicode(dis, 8);
            if (code.equals("0200")) return true;
            return false;
        }
        catch (Exception e)
        {
            return false;
        }
    }

    public static int fetch(KeyPair ecKeyPair, boolean increase){
        try ( Socket client = (Socket) sf.createSocket(SERVER_ADDRESS, SERVER_PORT);
            DataInputStream dis = new DataInputStream(client.getInputStream());
            DataOutputStream dos = new DataOutputStream(client.getOutputStream());){

            Gson gson = new Gson();
            SignedObject so = new SignedObject();
            so.objectString = gson.toJson(CustomECKeySpec.getPublicKeySpec(keyPair), CustomECKeySpec.class);
    
            byte[] signature = EthersUtils.signData(so.objectString.getBytes(StandardCharsets.US_ASCII), keyPair.getPrivate());
            so.signature = signature;
    
            String objectString = gson.toJson(so, SignedObject.class);
            System.out.println(objectString);

            dos.write(Tools.combine("0001".getBytes(StandardCharsets.UTF_16LE), Tools.data_with_ASCII_byte(objectString).getBytes(StandardCharsets.US_ASCII)));
            String code = Tools.receive_unicode(dis, 8);
            String result = Tools.receive_ASCII_Automatically(dis);

            num = Integer.parseInt(result); // comment this if error, and uncomment the line below
            // if (increase) num = num + 1;
            return num;
        }
        catch (Exception e){
            // if (increase) num = num + 1;
            return num;
        }
    }

    public static Boolean addVirus(KeyPair ecKeyPair, Virus virus){
        try (
            Socket client = (Socket) sf.createSocket(SERVER_ADDRESS, SERVER_PORT);
            DataInputStream dis = new DataInputStream(client.getInputStream());
            DataOutputStream dos = new DataOutputStream(client.getOutputStream());) {

            Gson gson = new Gson();
            SignedObject so = new SignedObject();

            // objectify virus
            so.objectString = gson.toJson(virus, Virus.class);

            byte[] signature = EthersUtils.signData(so.objectString.getBytes(StandardCharsets.US_ASCII), keyPair.getPrivate());
            so.signature = signature;

            String objectString = gson.toJson(so, SignedObject.class);

            dos.write(Tools.combine("0002".getBytes(StandardCharsets.UTF_16LE), Tools.data_with_ASCII_byte(objectString).getBytes(StandardCharsets.US_ASCII)));
            String code = Tools.receive_unicode(dis, 8);
            if (code.equals("0002")) return true;
            return false;
        }
        catch (Exception e) {
            return false;
        }
    }

    public static Boolean transfer(KeyPair ecKeyPair, String receiverPublicKey, long value){
        try (Socket client = (Socket) sf.createSocket(SERVER_ADDRESS, SERVER_PORT);
        DataInputStream dis = new DataInputStream(client.getInputStream());
        DataOutputStream dos = new DataOutputStream(client.getOutputStream());) {

            Gson gson = new Gson();
            SignedObject so = new SignedObject();
            Transfer transfer = new Transfer();
            transfer.senderPublicKey = CustomECKeySpec.getPublicKeySpec(keyPair);
            transfer.receiverPublicKey = gson.fromJson(receiverPublicKey, BigInteger.class);
            transfer.value = value;
            so.objectString = gson.toJson(transfer, Transfer.class);
    
            byte[] signature = EthersUtils.signData(so.objectString.getBytes(StandardCharsets.US_ASCII), keyPair.getPrivate());
            so.signature = signature;
    
            String objectString = gson.toJson(so, SignedObject.class);
            System.out.println(objectString);

            dos.write(Tools.combine("0003".getBytes(StandardCharsets.UTF_16LE), Tools.data_with_ASCII_byte(objectString).getBytes(StandardCharsets.US_ASCII)));
            String code = Tools.receive_unicode(dis, 8);
            if (code.equals("0003")) return true;
            return false;
        }
        catch (Exception e){
            return false;
        }
    }
}
