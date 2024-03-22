package app.narvi.example;

import static app.narvi.authz.PolicyRule.Decision.NOT_APPLICABLE;

import app.narvi.authz.Permission;
import app.narvi.authz.rules.BasicPolicyRule;

public class TestNotPermitRule implements BasicPolicyRule {

  @Override
  public String signature() {
    return "ey0B5B7r+Xe0boDDKk7eRqF6D3GyQDb7q6gSqdODSZoiowKQUaxR+7cjFRfH6beBe7G8IgJ1JZ/EINGVv++mxw==";
  }

  @Override
  public Decision evaluate(Permission permission) {
    return NOT_APPLICABLE;
  }
}
