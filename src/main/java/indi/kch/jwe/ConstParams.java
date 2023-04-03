package indi.kch.jwe;

import java.security.PrivateKey;
import java.security.PublicKey;

public class ConstParams {
    // rsa params
    static String rsa_publicKey_path = "C:\\Users\\Daniel\\Desktop\\Cer\\api-esipt.testesunbank.com.tw.cer";
    static String rsa_privateKey_path = "C:\\Users\\Daniel\\Desktop\\Cer\\api-esipt.testesunbank.com.tw.pfx";
    static String rsa_privateKey_alias = "3B62D331BC7E480F80258D9D762BFE78";
    static String rsa_privateKey_pswd = "Esun@1313";

    // algorithm
    static String rsa_algorithm = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    static String aes_algorithm = "AES/CBC/PKCS5Padding";
    static String mac_algorithm = "HmacSHA256";

    // byte unit
    static int aes_size = 256;
    static int iv_size = 16;
    static int mac_size = 16;
    static int enc_size = 16;

    // jwe constant params
    static String jwe_header_enc = "A128CBC-HS256";
    static String jwe_header_alg = "RSA-OAEP-256";
}
