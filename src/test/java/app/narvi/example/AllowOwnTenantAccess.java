package app.narvi.example;

import app.narvi.authz.Permission;
import app.narvi.authz.rules.BasicPolicyRule;

public class AllowOwnTenantAccess extends BasicPolicyRule {

  public AllowOwnTenantAccess(Permission permission) {
    super(permission);
  }

  @Override
  public Decision evaluate() {
    return Decision.NOT_APPLICABLE;
  }
}