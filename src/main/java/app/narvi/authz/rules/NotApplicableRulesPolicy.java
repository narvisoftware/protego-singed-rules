package app.narvi.authz.rules;

import app.narvi.authz.PolicyRule;
import app.narvi.authz.PolicyRulesProvider;

public class NotApplicableRulesPolicy implements PolicyRulesProvider {

  @Override
  public Iterable<PolicyRule> collect() {
    return null;
  }
}