package app.narvi.authz.rules.allownothing;

import static app.narvi.authz.PolicyRule.Decision.NOT_APPLICABLE;

import app.narvi.authz.Permission;
import app.narvi.authz.PolicyRule;

public class AllowNothingPolicyRule implements PolicyRule {

  @Override
  public Decision evaluate(Permission permission) {
    return NOT_APPLICABLE;
  }

}
