package app.narvi.protego.signatures.rules.sametenant;

import app.narvi.protego.Permission;
import app.narvi.protego.PolicyRule;

public class PermitNothingPolicyRule implements PolicyRule {

  @Override
  public boolean hasPermisssion(Permission permission) {
    return false;
  }

}
