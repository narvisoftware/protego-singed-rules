package app.narvi.authz.rules;

import java.util.ArrayList;
import java.util.List;

import app.narvi.authz.PolicyRule;
import app.narvi.authz.PolicyRulesProvider;
import app.narvi.authz.rules.conf.Configuration;

public class BasicPolicyRuleProvider implements PolicyRulesProvider {

  private final List<PolicyRule> policyRules = new ArrayList<>();

  public BasicPolicyRuleProvider() {
    verifyPolicyRulesSignatures();
  }

  @Override
  public Iterable<? super PolicyRule> collect() {
    return ((Iterable) policyRules);
  }


  public void verifyPolicyRulesSignatures() {
    Configuration.loadConfiguration();
  }

}
