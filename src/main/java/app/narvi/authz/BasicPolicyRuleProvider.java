package app.narvi.authz;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import javax.crypto.Cipher;

import app.narvi.authz.rules.NotApplicableRulesPolicy;

public class BasicPolicyRuleProvider implements PolicyRulesProvider {

  public static final String NEW_LINE_CHARACTER = "\n";
  public static final String PUBLIC_KEY_START_KEY_STRING = "-----BEGIN PUBLIC KEY-----";
  public static final String PUBLIC_KEY_END_KEY_STRING = "-----END PUBLIC KEY-----";
  public static final String EMPTY_STRING = "";
  public static final String NEW_CR_CHARACTER = "\r";
  private static final String ALGORITHM = "RSA";

  private final List<BasicPolicyRuleProvider> basicPolicyRules = new ArrayList<>();

  public static void main(String[] args) {
    BasicPolicyRuleProvider.of(new NotApplicableRulesPolicy());
  }

  public static void of(BasicPolicyRuleProvider... basicPolicyRule) {
    BasicPolicyRuleProvider newInstance = new BasicPolicyRuleProvider();

    try {
      for(BasicPolicyRuleProvider aPolicyRule: basicPolicyRule) {
        newInstance.verifyPolicyRuleSignature(aPolicyRule);
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    newInstance.basicPolicyRules.addAll(Arrays.asList(basicPolicyRule));
  }

  @Override
  public Iterable<BasicPolicyRule> collect() {
    return basicPolicyRules;
  }

  public void verifyPolicyRuleSignature(BasicPolicyRuleProvider basicPolicyRule) throws Exception {
    //gen sha-1
    String stringToHash = "app.narvi.example.AllowOwnTenantAccess";

    MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
    sha1.reset();
    sha1.update(stringToHash.getBytes(StandardCharsets.UTF_8));

    String hashString = Base64.getEncoder().encodeToString(sha1.digest());

    System.out.println("string to hash = " + stringToHash);
    System.out.println("sha1 = " + hashString);

    //decrypt
    //byte[] pubKeyBytes = Files.readAllBytes(Paths.get("/Users/mvasilache/prj/personal/clinic/protego-basic/src/main/resources/publicKey.pub"));
    byte[] pubKeyBytes = Sign2.class.getResourceAsStream("/publicKey.pub").readAllBytes();
    String publicKeyString = new String(pubKeyBytes, StandardCharsets.UTF_8);
    publicKeyString = publicKeyString.replaceAll(NEW_LINE_CHARACTER, EMPTY_STRING)
        .replaceAll(PUBLIC_KEY_START_KEY_STRING, EMPTY_STRING)
        .replaceAll(PUBLIC_KEY_END_KEY_STRING, EMPTY_STRING)
        .replaceAll(NEW_CR_CHARACTER, EMPTY_STRING);

    System.out.println("pubkey=" + publicKeyString);

    byte[] decoded = Base64
        .getDecoder()
        .decode(publicKeyString);

    KeySpec keySpec = new X509EncodedKeySpec(decoded);

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PublicKey publicKey = keyFactory.generatePublic(keySpec);

    final Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher2.init(Cipher.DECRYPT_MODE, publicKey);


    String enc = encryptedSha1();
    byte[] encryptedMessageHash = Base64.getDecoder().decode(enc);
    System.out.println("encrypted signature = " + Base64.getEncoder().encodeToString(encryptedMessageHash));

    byte[] decrypted = cipher2.doFinal(encryptedMessageHash);

//    String decodedString = Base64
//    .getEncoder()
//    .encodeToString(decrypted);

    String decryptedSignature = new String(decrypted, StandardCharsets.UTF_8);
    System.out.println();

    if(!hashString.equals(decryptedSignature)) {
      throw new SignatureException("signature does not match!");
    }
  }

  @Override
  public Decision evaluate(Permission permission) {
    return null;
  }

}
