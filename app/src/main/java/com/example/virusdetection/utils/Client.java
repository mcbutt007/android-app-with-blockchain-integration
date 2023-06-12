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
        String jsonBigInt = sharedPref.getString(context.getString(R.string.saved_key), "");
        Gson gson = new Gson();

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        if (jsonBigInt.equals("") || jsonBigInt.equals("1234") || jsonBigInt.equals("1020291192")){
            try {
                KeyPairGenerator keygen = KeyPairGenerator.getInstance("EC");
                ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
                keygen.initialize(ecSpec);
                KeyPair ecKeyPair = keygen.generateKeyPair();

                while(!Client.createNewAddress(ecKeyPair)){
                    ecKeyPair = keygen.generateKeyPair();
                }
                PrivateKey privateKey = ecKeyPair.getPrivate();
                BigInteger privateKeyBigInt = new BigInteger(1, privateKey.getEncoded());
                String privateKeyString = privateKeyBigInt.toString();
                privateKeyString = gson.toJson(privateKeyString, String.class);

                SharedPreferences.Editor editor = sharedPref.edit();
                editor.putString(context.getString(R.string.saved_key), privateKeyString);
                editor.apply();
                return ecKeyPair;
            } catch (NoSuchAlgorithmException | IOException | InvalidAlgorithmParameterException e) {
                throw new RuntimeException(e);
            }
        }
        BigInteger privateKeyBigInt = gson.fromJson(jsonBigInt, BigInteger.class);
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBigInt.toByteArray()));
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(privateKey.getEncoded()));
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
            PublicKey pub = ecKeyPair.getPublic();
            pub.toString();
            so.objectString = gson.toJson(ecKeyPair.getPublic(), BigInteger.class);

            // Print the private key.
            System.out.println(ecKeyPair.getPrivateKey());

            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(so.objectString.getBytes(StandardCharsets.US_ASCII));
            ECDSASignature signature = ecKeyPair.sign(digest);

            so.signature = signature;

            String objectString = gson.toJson(so, SignedObject.class);

            dos.write(Tools.combine("0200".getBytes(StandardCharsets.UTF_16LE), Tools.data_with_ASCII_byte(objectString).getBytes(StandardCharsets.US_ASCII)));
            String code = Tools.receive_unicode(dis, 8);
            if (code.equals("0200")) return true;
            return true;
        }
        catch (Exception e)
        {
            return true;
        }
    }

    public static int fetch(ECKeyPair ecKeyPair, boolean increase){
        try ( Socket client = (Socket) sf.createSocket(SERVER_ADDRESS, SERVER_PORT);
            DataInputStream dis = new DataInputStream(client.getInputStream());
            DataOutputStream dos = new DataOutputStream(client.getOutputStream());){

            // Print the public key.
            System.out.println(ecKeyPair.getPublicKey());

            Gson gson = new Gson();
            SignedObject so = new SignedObject();
            so.objectString = gson.toJson(ecKeyPair.getPublicKey(), BigInteger.class);

            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(so.objectString.getBytes(StandardCharsets.US_ASCII));
            ECDSASignature signature = ecKeyPair.sign(digest);

            so.signature = signature;

            String objectString = gson.toJson(so, SignedObject.class);

            dos.write(Tools.combine("0001".getBytes(StandardCharsets.UTF_16LE), Tools.data_with_ASCII_byte(objectString).getBytes(StandardCharsets.US_ASCII)));
            String code = Tools.receive_unicode(dis, 8);
            String result = Tools.receive_ASCII_Automatically(dis);
            if (increase) num = num + 1;
            return num;
        }
        catch (Exception e){
            if (increase) num = num + 1;
            return num;
        }
    }

    public static Boolean addVirus(ECKeyPair ecKeyPair, Virus virus){
        try (
            Socket client = (Socket) sf.createSocket(SERVER_ADDRESS, SERVER_PORT);
            DataInputStream dis = new DataInputStream(client.getInputStream());
            DataOutputStream dos = new DataOutputStream(client.getOutputStream());) {

            Gson gson = new Gson();
            SignedObject so = new SignedObject();

            // objectify virus
            so.objectString = gson.toJson(virus, Virus.class);

            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(so.objectString.getBytes(StandardCharsets.US_ASCII));
            ECDSASignature signature = ecKeyPair.sign(digest);

            so.signature = signature;

            String objectString = gson.toJson(so, SignedObject.class);

            dos.write(Tools.combine("0002".getBytes(StandardCharsets.UTF_16LE), Tools.data_with_ASCII_byte(objectString).getBytes(StandardCharsets.US_ASCII)));
            String code = Tools.receive_unicode(dis, 8);
            if (code.equals("0002")) return true;
            return true;
        }
        catch (Exception e) {
            return true;
        }
    }

    public static Boolean transfer(ECKeyPair ecKeyPair, String receiverPublicKey, long value){
        try (Socket client = (Socket) sf.createSocket(SERVER_ADDRESS, SERVER_PORT);
        DataInputStream dis = new DataInputStream(client.getInputStream());
        DataOutputStream dos = new DataOutputStream(client.getOutputStream());) {

            Gson gson = new Gson();
            SignedObject so = new SignedObject();
            Transfer transfer = new Transfer();
            transfer.senderPublicKey = ecKeyPair.getPublicKey();
            transfer.receiverPublicKey = gson.fromJson(receiverPublicKey, BigInteger.class);
            transfer.value = value;
            so.objectString = gson.toJson(transfer, Transfer.class);

            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(so.objectString.getBytes(StandardCharsets.US_ASCII));
            ECDSASignature signature = ecKeyPair.sign(digest);

            so.signature = signature;

            String objectString = gson.toJson(so, SignedObject.class);

            dos.write(Tools.combine("0003".getBytes(StandardCharsets.UTF_16LE), Tools.data_with_ASCII_byte(objectString).getBytes(StandardCharsets.US_ASCII)));
            String code = Tools.receive_unicode(dis, 8);
            if (code.equals("0003")) return true;
            return true;
        }
        catch (Exception e){
            return true;
        }
    }
}
