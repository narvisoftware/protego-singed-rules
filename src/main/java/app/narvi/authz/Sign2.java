package app.narvi.authz;

import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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

  public static void main(String[] args) throws Exception {

    publicKey = publicKey.replaceAll(NEW_LINE_CHARACTER, EMPTY_STRING)
        .replaceAll(PUBLIC_KEY_START_KEY_STRING, EMPTY_STRING)
        .replaceAll(PUBLIC_KEY_END_KEY_STRING, EMPTY_STRING)
        .replaceAll(NEW_CR_CHARACTER, EMPTY_STRING);

    MessageDigest crypt = MessageDigest.getInstance("SHA-1");
    crypt.reset();
    crypt.update("app.narvi.example.AllowOwnTenantAccess".getBytes("UTF-8"));

    String digest = Base64.getEncoder().encodeToString(crypt.digest());

    System.out.println("sha1;" + digest);

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
    String base64EncodedEncryptedBytes = Base64.getEncoder().encodeToString(encryptedMessageHash);
    System.out.println("enc:" + base64EncodedEncryptedBytes);
    
    byte[] decoded = Base64
        .getDecoder()
        .decode(publicKey);

    KeySpec keySpec
        = new X509EncodedKeySpec(decoded);

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PublicKey publicKeyk = keyFactory.generatePublic(keySpec);

    final Cipher cipher2 = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    cipher2.init(Cipher.DECRYPT_MODE, publicKeyk);
    byte[] decoded_ = Base64
        .getDecoder()
        .decode(base64EncodedEncryptedBytes);
    byte[] decrypted = cipher.doFinal(decoded_);
  }
}
