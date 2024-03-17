package app.narvi.authz;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import javax.crypto.Cipher;

import app.narvi.authz.rules.NotApplicableRulesPolicy;

public class BasicPolicyRule implements PolicyRule {

  public static final String NEW_LINE_CHARACTER = "\n";
  public static final String PUBLIC_KEY_START_KEY_STRING = "-----BEGIN PUBLIC KEY-----";
  public static final String PUBLIC_KEY_END_KEY_STRING = "-----END PUBLIC KEY-----";
  public static final String EMPTY_STRING = "";
  public static final String NEW_CR_CHARACTER = "\r";
  private static final String ALGORITHM = "RSA";

  private final List<BasicPolicyRule> basicPolicyRules = new ArrayList<>();

  public static void main(String[] args) {
    BasicPolicyRule.of(new NotApplicableRulesPolicy());
  }

  public static void of(BasicPolicyRule... basicPolicyRule) {
    BasicPolicyRule newInstance = new BasicPolicyRule();
    newInstance.basicPolicyRules.addAll(Arrays.asList(basicPolicyRule));
    try {
      newInstance.verifyPolicyRuleSignature(basicPolicyRule[0]);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public void verifyPolicyRuleSignature(BasicPolicyRule basicPolicyRule) throws Exception {
    //gen sha-1

    String stringToHash = "app.narvi.example.AllowOwnTenantAccess";

    MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
    sha1.reset();
    sha1.update(stringToHash.getBytes(StandardCharsets.UTF_8));
    System.out.println("sha1 = " + stringToHash);


    //decrypt
    byte[] pubKeyBytes = Files.readAllBytes(Paths.get("publicKey.pub"));
    String publicKeyString = new String(pubKeyBytes, StandardCharsets.UTF_8);
    publicKeyString = publicKeyString.replaceAll(NEW_LINE_CHARACTER, EMPTY_STRING)
        .replaceAll(PUBLIC_KEY_START_KEY_STRING, EMPTY_STRING)
        .replaceAll(PUBLIC_KEY_END_KEY_STRING, EMPTY_STRING)
        .replaceAll(NEW_CR_CHARACTER, EMPTY_STRING);

    byte[] decoded = Base64
        .getDecoder()
        .decode(publicKeyString);

    KeySpec keySpec = new X509EncodedKeySpec(decoded);

    KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
    PublicKey publicKey = keyFactory.generatePublic(keySpec);

    final Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher2.init(Cipher.DECRYPT_MODE, publicKey);

    byte[] decrypted = cipher2.doFinal(basicPolicyRule.encryptedSha1().getBytes(StandardCharsets.UTF_8));
    System.out.println("encrypted = " + Base64.getEncoder().encodeToString(decrypted));

    System.out.println("decrypt = " + new String(decrypted, StandardCharsets.UTF_8));
  }

  @Override
  public Decision evaluate(Permission permission) {
    return null;
  }

  public String encryptedSha1() {
    return "u2u1L7i71V5NDyn+rAg2wcT5s/HBvGEf3Gg78QQH86uyjcN4LlwmaAzMNQqLH/Kn4CamjYLbo13vmTy5uN4rHQ==";
  }
}
