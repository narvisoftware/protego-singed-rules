package app.narvi.protego.signatures.rules;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import app.narvi.protego.PolicyRule;
import app.narvi.protego.PolicyRulesProvider;
import app.narvi.protego.signatures.rules.conf.Configuration;
import app.narvi.protego.signatures.rules.conf.PolicyRuleCofiguration;

public class SignedPolicyRuleProvider implements PolicyRulesProvider {

  private final List<PolicyRule> policyRules = new ArrayList<>();

  public SignedPolicyRuleProvider() {
    verifyPolicyRulesSignatures();
  }

  @Override
  public Iterable<? super PolicyRule> collect() {
    return Collections.unmodifiableCollection(policyRules);
  }


  public void verifyPolicyRulesSignatures() {
    try {
      Configuration configuration = Configuration.loadConfiguration();
      for (PolicyRuleCofiguration aPolicyRuleConf : configuration.getPolicyRuleCofigurations()) {
        Class aPolicyClass = Class.forName(aPolicyRuleConf.getClassName());
        policyRules.add((PolicyRule) aPolicyClass.getConstructor().newInstance());
      }
    } catch (Exception e) {
      throw new RuntimeException("Cannot load policy rules.", e);
    }

  }

}
