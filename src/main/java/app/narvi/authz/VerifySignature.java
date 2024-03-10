package app.narvi.authz;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
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

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PublicKey pubKey =keyFactory.generatePublic(pubKeySpec);

    Signature sig = Signature.getInstance("SHA1withRSA");

    sig.initVerify(pubKey);

    String signature= "rt3SK2juB5pEYKWh0mVyZOwh6z7RQLWRlSY1/NbLgNpVhVPLJrfClzNVFbbkSEJdwjm4R0DSw+4Z8yef87QORA==";

    byte[] sigToVerify = Base64.getDecoder().decode(signature);

    byte[] dataBytes = Base64.getEncoder().encode("app.narvi.example.AllowOwnTenantAccess".getBytes(StandardCharsets.UTF_8));
    //dataBytes = Base64.getDecoder().decode(dataBytes);

    MessageDigest crypt = MessageDigest.getInstance("SHA-1");
    crypt.reset();
    crypt.update("app.narvi.example.AllowOwnTenantAccess".getBytes("UTF-8"));

    String digest = Base64.getEncoder().encodeToString(crypt.digest());
    byte[] digest1 = Base64.getEncoder().encode(crypt.digest());
    System.out.println("sha1;" + digest);

    sig.update(digest1);
    boolean verifies = sig.verify(sigToVerify);

    System.out.println(verifies);

  }
}
