package app.narvi.example;

import static app.narvi.authz.PolicyRule.Decision.NOT_APPLICABLE;

import app.narvi.authz.Permission;
import app.narvi.authz.rules.BasicPolicyRule;

public class TestNotPermitRule implements BasicPolicyRule {

  @Override
  public String signature() {
    return "pvFbHwEyVDK4eaYD0Bxo3hVtlgfwY/p2iGBzdmZT/lah90etrg99rlqmjAQ9RSYd6MT2COpRbfWHG+uG3QxvzQ==";
  }

  @Override
  public Decision evaluate(Permission permission) {
    return NOT_APPLICABLE;
  }
}
