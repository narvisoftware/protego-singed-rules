package app.narvi.authz;

import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

public class Sign2 {
  
  public static final String NEW_LINE_CHARACTER = "\n";
  public static final String PUBLIC_KEY_START_KEY_STRING = "-----BEGIN PUBLIC KEY-----";
  public static final String PUBLIC_KEY_END_KEY_STRING = "-----END PUBLIC KEY-----";
  public static final String EMPTY_STRING = "";
  public static final String NEW_CR_CHARACTER = "\r";

  private static String publicKey = """
      -----BEGIN PUBLIC KEY-----
      MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAM2AWfWKaoXuaLly5+0J6i6MXHCKvZSt
      wA7i00FG+duQLnvpaolJG7KEnBRaQkH7adUKEdeJWLIUeN449x2xyv0CAwEAAQ==
      -----END PUBLIC KEY-----
      """;
    publicKey = publicKey.replaceAll(NEW_LINE_CHARACTER, EMPTY_STRING)
            .replaceAll(PUBLIC_KEY_START_KEY_STRING, EMPTY_STRING)
            .replaceAll(PUBLIC_KEY_END_KEY_STRING, EMPTY_STRING)
            .replaceAll(NEW_CR_CHARACTER, EMPTY_STRING);

  public static void main(String[] args) throws Exception {
    MessageDigest crypt = MessageDigest.getInstance("SHA-1");
    crypt.reset();
    crypt.update("app.narvi.example.AllowOwnTenantAccess".getBytes("UTF-8"));

    String digest = Base64.getEncoder().encodeToString(crypt.digest());

    System.out.println("sha1;" + digest);

    KeyFactory keyFactory_ = KeyFactory.getInstance("RSA");

    File pkcsKeyFile_ = new File("key.pkcs8" );
    FileInputStream is = new FileInputStream( "key.pkcs8" );

    int offset = 0;
    int read = 0;
    final long length = pkcsKeyFile_.length();
    byte [] keyFileBytes_ = new byte[(int)length];
    while ( offset < keyFileBytes_.length
        && (read=is.read(keyFileBytes_, offset,
        keyFileBytes_.length-offset)) >= 0 ) {
      offset += read;
    }

    PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(keyFileBytes_);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    RSAPrivateKey privKey = (RSAPrivateKey) kf.generatePrivate(privKeySpec);

    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.ENCRYPT_MODE, privKey);
    byte[] encryptedMessageHash = cipher.doFinal(digest.getBytes(StandardCharsets.UTF_8));
    System.out.println("enc:" +
        Base64.getEncoder().encodeToString(encryptedMessageHash)
    );

    PKCS8EncodedKeySpec privKeySpec2 = new PKCS8EncodedKeySpec(keyFileBytes_);
    KeyFactory kf2 = KeyFactory.getInstance("RSA");
    RSAPrivateKey privKey2 = (RSAPrivateKey) kf.generatePrivate(privKeySpec2);

    Cipher cipher2 = Cipher.getInstance("RSA");
    cipher2.init(Cipher.DECRYPT_MODE, privKey);

    cipher2.update(encryptedMessageHash);
    System.out.println(
      cipher2.doFinal()
      //cipher2.doFinal(encryptedMessageHash)
    );
  }
}
