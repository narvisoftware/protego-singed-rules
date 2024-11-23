package app.narvi.protego.signatures.rules.sametenant;

import static app.narvi.protego.signatures.rules.sametenant.User.AUTHENTICATED_USER;

import app.narvi.authz.Permission;
import app.narvi.authz.PolicyRule;

public class AllowOwnTenantPolicyRule implements PolicyRule {

  @Override
  public boolean hasPermisssion(Permission permission) {
    if (!(permission instanceof TenantAccessPermission)) {
      return false;
    }
    User authenticatedUser = AUTHENTICATED_USER.get();
    return ((TenantAccessPermission) permission).getProtectedResource().getTenantOwner()
        .equals(authenticatedUser.getTenantOwner());
  }
}
