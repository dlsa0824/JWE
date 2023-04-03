/*
Implementation for jwe with A128CBC-HS256 and RSA-OAEP-256
 */

package indi.kch.jwe;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

public class Main {
    public static void main (String args []) throws Exception {

        String plainText = "Sorry that i love you";

        Jwe jwe = new Jwe();

        String encryptedMsg = jwe.encrypt(plainText);
        System.out.println(jsonToPretty(encryptedMsg));

        String decryptedMsg = jwe.decrypt(encryptedMsg);
        System.out.println(decryptedMsg);
    }

    public static String jsonToPretty(String input) {

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        JsonObject jsonObj = new Gson().fromJson(input, JsonObject.class);

        return gson.toJson(jsonObj);
    }
}
