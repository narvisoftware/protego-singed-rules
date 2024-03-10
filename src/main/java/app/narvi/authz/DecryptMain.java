package app.narvi.authz;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

public class DecryptMain {

  private static String publicKey = """
      -----BEGIN PUBLIC KEY-----
      MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAM2AWfWKaoXuaLly5+0J6i6MXHCKvZSt
      wA7i00FG+duQLnvpaolJG7KEnBRaQkH7adUKEdeJWLIUeN449x2xyv0CAwEAAQ==
      -----END PUBLIC KEY-----
      """;

  public static PublicKey publicKeyk;

  public static void main(String[] args) throws Exception {
      setPublicKey();
      decryptFromBase64();
  }

  public static String decryptFromBase64() {
    String base64EncodedEncryptedBytes = "AEDDD22B68EE079A4460A5A1D2657264EC21EB3ED140B591952635FCD6CB80DA558553CB26B7C297335515B6E448425DC239B84740D2C3EE19F3279FF3B40E44";
    String plainText = null;
    try {
      final Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
      cipher.init(Cipher.DECRYPT_MODE, publicKeyk);
      byte[] decoded = Base64
          .getDecoder()
          .decode(base64EncodedEncryptedBytes);
      byte[] decrypted = cipher.doFinal(decoded);
      plainText = new String(decrypted);
      System.out.println(plainText);
    } catch (Exception ex) {
      ex.printStackTrace();
    }
    return plainText;
  }

  protected static void setPublicKey()
      throws Exception {

    byte[] decoded = Base64
        .getDecoder()
        .decode(publicKey.replaceAll("\n", "")
        .replaceAll("-----BEGIN PUBLIC KEY-----", "")
        .replaceAll("-----END PUBLIC KEY-----", ""));

    KeySpec keySpec
        = new X509EncodedKeySpec(decoded);

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    publicKeyk = keyFactory.generatePublic(keySpec);
  }
}
