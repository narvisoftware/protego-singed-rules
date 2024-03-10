package app.narvi.authz;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

public class EncryptMain {

  public static final String NEW_LINE_CHARACTER = "\n";
  public static final String PUBLIC_KEY_START_KEY_STRING = "-----BEGIN PUBLIC KEY-----";
  public static final String PUBLIC_KEY_END_KEY_STRING = "-----END PUBLIC KEY-----";
  public static final String EMPTY_STRING = "";
  public static final String NEW_CR_CHARACTER = "\r";
  private static final String ALGORITHM = "RSA";

  private static String publicKey = """
      -----BEGIN PUBLIC KEY-----
      MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAM2AWfWKaoXuaLly5+0J6i6MXHCKvZSt
      wA7i00FG+duQLnvpaolJG7KEnBRaQkH7adUKEdeJWLIUeN449x2xyv0CAwEAAQ==
      -----END PUBLIC KEY-----
      """;

  public static void main(String[] args) {
    publicKey = publicKey.replaceAll(NEW_LINE_CHARACTER, EMPTY_STRING)
        .replaceAll(PUBLIC_KEY_START_KEY_STRING, EMPTY_STRING)
        .replaceAll(PUBLIC_KEY_END_KEY_STRING, EMPTY_STRING)
        .replaceAll(NEW_CR_CHARACTER, EMPTY_STRING);

    byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey.getBytes(StandardCharsets.UTF_8));
    try {
      byte[] encryptedData = encrypt(publicKeyBytes,
          "ANOTAYEH46GCA2L57OZZKN0CWULSWCLUSHTSMRL03H5NJNJG9G2V4TN26OJAB53P6YJL9RMYZ6G+A7VX1ZI6WA==".getBytes());

      String encryptedString = Base64.getEncoder().encodeToString(encryptedData);

      System.out.println("Output encryptedString: " + encryptedString);
    } catch (Exception e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
  }

  public static byte[] encrypt(byte[] publicKey, byte[] inputData)
      throws Exception {

    PublicKey key = KeyFactory.getInstance(ALGORITHM)
        .generatePublic(new X509EncodedKeySpec(publicKey));

    Cipher cipher = Cipher.getInstance(ALGORITHM);
    cipher.init(Cipher.ENCRYPT_MODE, key);

    byte[] encryptedBytes = cipher.doFinal(inputData);

    return encryptedBytes;
  }

}
