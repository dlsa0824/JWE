package indi.kch.jwe;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Rsa {

    PublicKey publicKey;
    PrivateKey privateKey;

    public Rsa() throws Exception {
        // Use Bouncy Castle Provider -> defaut go wrong with sha1 padding
        Security.addProvider(new BouncyCastleProvider());

        // load rsa public key
        FileInputStream fileInputStream_pubKey = new FileInputStream(ConstParams.rsa_publicKey_path);
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        X509Certificate crt = (X509Certificate) cf.generateCertificate(fileInputStream_pubKey);
        publicKey = crt.getPublicKey();

        // load rsa private key
        FileInputStream fileInputStream_prvKey = new FileInputStream(ConstParams.rsa_privateKey_path);
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(fileInputStream_prvKey, ConstParams.rsa_privateKey_pswd.toCharArray());
        privateKey = (PrivateKey) keystore.getKey(ConstParams.rsa_privateKey_alias, ConstParams.rsa_privateKey_pswd.toCharArray());
    }

    public byte[] encrypt(byte[] encKey) throws Exception {
        Cipher cipher= Cipher.getInstance(ConstParams.rsa_algorithm, BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(encKey);
    }

    public byte[] decrypt(byte[] encryptedKey) throws Exception {
        Cipher cipher= Cipher.getInstance(ConstParams.rsa_algorithm, BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedKey);
    }
}
