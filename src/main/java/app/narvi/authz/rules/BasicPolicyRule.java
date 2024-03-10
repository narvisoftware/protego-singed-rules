package app.narvi.authz.rules;

import app.narvi.authz.Action;
import app.narvi.authz.Permission;
import app.narvi.authz.PolicyRule;

public abstract class BasicPolicyRule implements PolicyRule {

  public Decision evaluate(Permission permission) {
    return Decision.NOT_APPLICABLE;
  }


}