package app.narvi.example;

import static app.narvi.authz.PolicyRule.Decision.NOT_APPLICABLE;

import app.narvi.authz.Permission;
import app.narvi.authz.rules.BasicPolicyRule;

public class TestNotPermitRule implements BasicPolicyRule {

  @Override
  public String signature() {
    return "Wdu4qjOapGqyypt0qycK2JYZyDZj42r3oM+ByvL+E9juI4oOjyLnXtnYuTG2SRgsBtU+Xb9+nTYyG/q3VVeW9w==";
  }

  @Override
  public Decision evaluate(Permission permission) {
    return NOT_APPLICABLE;
  }
}
