package indi.kch.jwe;

import org.json.JSONArray;
import org.json.JSONObject;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

public class Jwe {

    Base64Url base64Url;
    Rsa rsa;
    Aes aes;

    public Jwe() throws Exception {
        base64Url = new Base64Url();
        rsa = new Rsa();
        aes = new Aes();
    }

    public String encrypt(String plainText) throws Exception{
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(ConstParams.aes_size);
        SecretKey secretKey = keyGenerator.generateKey();
        byte[] cek = secretKey.getEncoded();

        // Split cek -> first 128 byte is hmac for validating data, second 128 byte is enc for encrypting plaintext
        byte[] hmac = new byte[ConstParams.mac_size];
        System.arraycopy(cek, 0, hmac, 0, hmac.length);
        byte[] enc = new byte[ConstParams.enc_size];
        System.arraycopy(cek, hmac.length, enc, 0, enc.length);

        byte[] iv = new byte[ConstParams.iv_size];
        new SecureRandom().nextBytes(iv);

        // form jwe protected value
        JSONObject protectedObj = new JSONObject();
        protectedObj.put("enc", ConstParams.jwe_header_enc);
        protectedObj.put("alg", ConstParams.jwe_header_alg);
        String protectedStr = base64Url.encode(protectedObj.toString().getBytes());

        byte[] encryptedKey = rsa.encrypt(cek);

        byte[] ciphertext = aes.encrypt(plainText.getBytes(), enc, iv);

        byte[] tag = generateTag(protectedStr, iv, ciphertext, hmac);

        // form recipients array
        ArrayList<JSONObject> recipientsArray = new ArrayList<>();
        JSONObject recipientObj = new JSONObject();
        recipientObj.put("encrypted_key", base64Url.encode(encryptedKey));
        recipientsArray.add(recipientObj);

        // Form jwe object
        JSONObject jweObj = new JSONObject();
        jweObj.put("recipients", recipientsArray);
        jweObj.put("protected", protectedStr);
        jweObj.put("ciphertext", base64Url.encode(ciphertext));
        jweObj.put("iv", base64Url.encode(iv));
        jweObj.put("tag", base64Url.encode(tag));

        return jweObj.toString();
    }

    public String decrypt(String jweObjStr) throws Exception {

        JSONObject jweObj = new JSONObject(jweObjStr);

        JSONArray recipients = jweObj.getJSONArray("recipients");
        String encrypted_key = recipients.getJSONObject(0).getString("encrypted_key");;
        String protectedStr = jweObj.getString("protected");
        String ciphertext = jweObj.getString("ciphertext");
        String iv = jweObj.getString("iv");
        String tag = jweObj.getString("tag");

        byte[] cek = rsa.decrypt(base64Url.decode(encrypted_key));

        //Split cek -> first 128 byte is hmac for validating data, second 128 byte is enc for encrypting plaintext
        byte[] hmac = new byte[ConstParams.mac_size];
        System.arraycopy(cek, 0, hmac, 0, hmac.length);
        byte[] enc = new byte[ConstParams.enc_size];
        System.arraycopy(cek, hmac.length, enc, 0, enc.length);

        // Validate tag
        byte[] validatedTag = generateTag(protectedStr, base64Url.decode(iv), base64Url.decode(ciphertext), hmac);
        if (!Arrays.equals(validatedTag, base64Url.decode(tag))) {
            throw new Exception("Tag Authenticate Failed");
        }

        byte[] plainText = aes.decrypt(base64Url.decode(ciphertext), enc, base64Url.decode(iv));

        return new String(plainText);
    }

    private byte[] generateTag(String protectedStr, byte[] iv, byte[] ciphertext, byte[] hmac) throws Exception {
        byte[] aad = protectedStr.getBytes(StandardCharsets.US_ASCII);
        byte[] octets = bigEndianOf64Bit(protectedStr.length() * 8);

        byte[] concateData = new byte[aad.length + iv.length + ciphertext.length + octets.length];
        System.arraycopy(aad, 0, concateData, 0, aad.length);
        System.arraycopy(iv, 0, concateData, aad.length, iv.length);
        System.arraycopy(ciphertext, 0, concateData, aad.length + iv.length, ciphertext.length);
        System.arraycopy(octets, 0, concateData, aad.length + iv.length + ciphertext.length, octets.length);

        // hmac-256
        Key hmacKey = new SecretKeySpec(hmac, ConstParams.mac_algorithm);
        Mac hmacSHA256 = Mac.getInstance(ConstParams.mac_algorithm);
        hmacSHA256.init(hmacKey);
        byte [] macData = hmacSHA256.doFinal(concateData);

        // first half of mac
        byte[] tag = new byte[macData.length/2];
        System.arraycopy(macData, 0, tag, 0, tag.length);

        return tag;
    }

    private byte[] bigEndianOf64Bit(int length) {
        byte[] buffer = new byte[4];
        buffer[0] = (byte) (length >> 24);
        buffer[1] = (byte) (length >> 16);
        buffer[2] = (byte) (length >> 8);
        buffer[3] = (byte) length;

        byte[] bigEndian = new byte[8];
        System.arraycopy(buffer, 0, bigEndian, 4, buffer.length);

        return bigEndian;
    }
}
