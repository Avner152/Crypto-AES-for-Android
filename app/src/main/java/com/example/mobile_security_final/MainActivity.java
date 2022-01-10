package com.example.mobile_security_final;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    private Button encrypt_btn, decrypt_btn;
    private EditText message_text ;
    private String msg_input ="", cipher = "", algorithm = "AES/CBC/PKCS5Padding";
    private SecretKey key;
    IvParameterSpec ivParameterSpec;

    @RequiresApi(api = Build.VERSION_CODES.O)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        inits();
        listeners();
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    private void inits() {
        encrypt_btn = findViewById(R.id.enc_main_btn);
        decrypt_btn = findViewById(R.id.dcr_main_btn);
        message_text = findViewById(R.id.message_text);

//        Init Key and IV:
        try {
            key = generateKey(128);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        ivParameterSpec = generateIv();
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    private void listeners() {
        encrypt_btn.setOnClickListener(v -> {
            msg_input = message_text.getText().toString();
            Log.i("ENC", "PlainText: " + msg_input);
            try {
                cipher = encrypt(algorithm,msg_input , key, ivParameterSpec);
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            }
            Log.i("ENC", "Cipher: " + cipher);
        });


        decrypt_btn.setOnClickListener(v -> {
            cipher = message_text.getText().toString();
            try {
                Log.i("DEC", "Cipher: " + cipher);
                msg_input = decrypt(algorithm, cipher, key, ivParameterSpec);
                Log.i("DEC", "PlainText: " + msg_input);
            } catch (IllegalArgumentException e){
                Log.i("TAG", "listeners: STFU");
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            }
        });
    }

    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
        public static String encrypt(String algorithm, String input, SecretKey key,
                                 IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder()
                .encodeToString(cipherText);
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    public static String decrypt(String algorithm, String cipherText, SecretKey key,
                                 IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText;
        try {
            plainText = cipher.doFinal(Base64.getDecoder()
                    .decode(cipherText));
        }catch (Error e){
            return "";
        }
        return new String(plainText);
    }
}