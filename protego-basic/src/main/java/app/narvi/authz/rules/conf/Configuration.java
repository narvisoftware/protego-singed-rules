package app.narvi.authz.rules.conf;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class Configuration {

  private String publicKey;
  private List<PolicyRuleCofiguration> policyRuleCofigurations = new ArrayList<>();

  private static final String SIGNATURES_FILE_NAME = "protego-policy-rules-and-signatures.yml";
  private static final String FILE_NAME_PROPERTY = "policyRulesFileName";

  private Configuration() {
  }

  public static Configuration loadConfiguration() {
    Yaml yaml = new Yaml(new Constructor(Configuration.class, new LoaderOptions()));

    InputStream inputStream;
    if(System.getProperty(FILE_NAME_PROPERTY) == null) {
      inputStream = Configuration.class.getClassLoader().getResourceAsStream(SIGNATURES_FILE_NAME);
    } else {
      inputStream = Configuration.class.getClassLoader().getResourceAsStream(System.getProperty(FILE_NAME_PROPERTY));
    }

    Configuration conf = yaml.load(inputStream);
    conf.validateSignatures();

    return conf;
  }

  private void validateSignatures() {
    for(PolicyRuleCofiguration aPolicyRuleConfig : policyRuleCofigurations) {
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
