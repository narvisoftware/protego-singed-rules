package app.narvi.authz.rules.sametenant;

import app.narvi.authz.CrudAction;
import app.narvi.authz.Permission;

public class TenantAccessPermission extends Permission<CrudAction, TenantResource> {

  public TenantAccessPermission(CrudAction action, TenantResource protectedResource) {
    super(action, protectedResource);
  }
}
