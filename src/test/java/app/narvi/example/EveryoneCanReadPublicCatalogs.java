package app.narvi.example;

import app.narvi.authz.Permission;
import app.narvi.authz.rules.BasicPolicyRule;

public class EveryoneCanReadPublicCatalogs extends BasicPolicyRule {

  public EveryoneCanReadPublicCatalogs(Permission permission) {
    super(permission);
  }

  @Override
  public Decision evaluate() {
    return Decision.NOT_APPLICABLE;
  }
}