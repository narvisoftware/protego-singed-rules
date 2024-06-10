package app.narvi.authz.rules;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import app.narvi.authz.PolicyRule;
import app.narvi.authz.PolicyRulesProvider;
import app.narvi.authz.rules.conf.Configuration;
import app.narvi.authz.rules.conf.PolicyRuleCofiguration;

public class BasicPolicyRuleProvider implements PolicyRulesProvider {

  private final List<PolicyRule> policyRules = new ArrayList<>();

  public BasicPolicyRuleProvider() {
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
