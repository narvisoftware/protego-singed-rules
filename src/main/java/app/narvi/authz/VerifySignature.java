package app.narvi.authz;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class VerifySignature {
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
    byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey.getBytes(StandardCharsets.UTF_8));

    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyBytes);

    KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
    PublicKey pubKey =keyFactory.generatePublic(pubKeySpec);

    Signature sig = Signature.getInstance("SHA1withDSA", "SUN");

    sig.initVerify(pubKey);

    byte[] sigToVerify = Base64.getDecoder().decode("AEDDD22B68EE079A4460A5A1D2657264EC21EB3ED140B591952635FCD6CB80DA558553CB26B7C297335515B6E448425DC239B84740D2C3EE19F3279FF3B40E44");

    boolean verifies = sig.verify(sigToVerify);

    System.out.println(verifies);

  }
}
