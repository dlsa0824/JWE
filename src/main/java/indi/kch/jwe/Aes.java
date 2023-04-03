package indi.kch.jwe;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Aes {

    public static byte[] encrypt(byte[] plaintext, byte[] encKey, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ConstParams.aes_algorithm);
        SecretKey secretKey = new SecretKeySpec(encKey, 0, encKey.length, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

        byte[] ciphertext = cipher.doFinal(plaintext);
        return ciphertext;
    }

    public static byte[] decrypt(byte[] encryptedtext, byte[] encKey, byte[] iv) throws Exception{
        Cipher cipher = Cipher.getInstance(ConstParams.aes_algorithm);
        SecretKey secretKey = new SecretKeySpec(encKey, 0, encKey.length, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        byte[] plainText = cipher.doFinal(encryptedtext);
        return plainText;
    }
}
