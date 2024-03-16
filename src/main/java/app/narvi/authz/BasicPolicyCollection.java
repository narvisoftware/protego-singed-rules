package app.narvi.authz;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import app.narvi.authz.rules.NotApplicableRulesPolicy;

import javax.crypto.Cipher;

import app.narvi.authz.PolicyEvaluator;
import app.narvi.authz.PolicyRulesProvider;
import app.narvi.authz.RulesCollection;

public class BasicPolicyCollection implements RulesCollection {

  public static final String NEW_LINE_CHARACTER = "\n";
  public static final String PUBLIC_KEY_START_KEY_STRING = "-----BEGIN PUBLIC KEY-----";
  public static final String PUBLIC_KEY_END_KEY_STRING = "-----END PUBLIC KEY-----";
  public static final String EMPTY_STRING = "";
  public static final String NEW_CR_CHARACTER = "\r";
  private static final String ALGORITHM = "RSA";

  private final List<PolicyRulesProvider> rulesProviders = List.of(
      () -> Arrays.asList(
          new NotApplicablePolicyRulesProvider()
      )
  );

  public BasicPolicyCollection() {
    PolicyEvaluator.registerRulesCollection(this);
  }

  @Override
  public Iterable<PolicyRulesProvider> getRulesProviders() {
    return rulesProviders;
  }

  public void checkPolicyRule() {
    
  }


}
