package app.narvi.authz.rules;

import static app.narvi.authz.PolicyRule.Decision.NOT_APPLICABLE;

import app.narvi.authz.Permission;

public class AllowNothingPolicyRule implements BasicPolicyRule {

  @Override
  public Decision evaluate(Permission permission) {
    return NOT_APPLICABLE;
  }

  @Override
  public String signature() {
    return "RaJmqvsWeb+9bWMQiHnHarzAb6UawCHt+DDhtN02UYffU67Fp4tgcEHrfiEgU2RQYlo31ga2cYR/ns74zPZQAw==";
  }

}
