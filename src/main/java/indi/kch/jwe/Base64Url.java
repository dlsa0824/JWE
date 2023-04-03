package indi.kch.jwe;

import java.util.Base64;

public class Base64Url {

    Base64.Encoder encoder = Base64.getEncoder();
    Base64.Decoder decoder = Base64.getDecoder();

    public String encode(byte[] input) {
        return encoder.encodeToString(input).split("=")[0].replace("+", "-").replace("/", "_");
    }

    public byte[] decode (String input) {
        return decoder.decode(input.replace("-", "+").replace("_", "/"));
    }
}
