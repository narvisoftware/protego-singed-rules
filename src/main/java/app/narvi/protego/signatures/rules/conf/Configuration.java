package app.narvi.protego.signatures.rules.conf;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

public class Configuration {

  private String publicKey;
  private List<PolicyRuleCofiguration> policyRuleCofigurations = new ArrayList<>();

  private static final String SIGNATURES_FILE_NAME = "protego-policy-rules-and-signatures.yaml";
  public static final String FILE_NAME_PROPERTY = "policyRulesFileName";

  protected Configuration() {
  }

  public static Configuration loadConfiguration() {
    Yaml yaml = new Yaml(new Constructor(Configuration.class, new LoaderOptions()));

    InputStream inputStream;
    if (System.getProperty(FILE_NAME_PROPERTY) == null) {
      inputStream = Configuration.class.getClassLoader().getResourceAsStream(SIGNATURES_FILE_NAME);
    } else {
      inputStream = Configuration.class.getClassLoader().getResourceAsStream(System.getProperty(FILE_NAME_PROPERTY));
    }

    Configuration conf = yaml.load(inputStream);
    conf.validateSignatures();

    return conf;
  }

  public static String decrypt(String input) throws Exception {
    Configuration configuration = Configuration.loadConfiguration();
    PolicyRuleCofiguration emptyRuleCofiguration = new PolicyRuleCofiguration();
    byte[] decrypted = emptyRuleCofiguration.decrypt(configuration.publicKey.replaceAll("\s", ""), input);
    return new String(decrypted, StandardCharsets.UTF_8);
  }

  protected void validateSignatures() {
    for (PolicyRuleCofiguration aPolicyRuleConfig : policyRuleCofigurations) {
      aPolicyRuleConfig.verifySignature(publicKey.replaceAll("\s", ""));
    }
  }

  public String getPublicKey() {
    return publicKey;
  }

  public void setPublicKey(String publicKey) {
    this.publicKey = publicKey;
  }

  public List<PolicyRuleCofiguration> getPolicyRuleCofigurations() {
    return policyRuleCofigurations;
  }

  public void setPolicyRuleCofigurations(List<PolicyRuleCofiguration> policyRuleCofigurations) {
    this.policyRuleCofigurations = new ArrayList<>(policyRuleCofigurations);
  }

  public void addPolicyRuleCofigurations(
      List<PolicyRuleCofiguration> policyRuleCofigurations) {
    this.policyRuleCofigurations = policyRuleCofigurations;
  }
}
