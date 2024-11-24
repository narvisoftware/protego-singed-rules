package app.narvi.protego.signatures.rules.sametenant;

import app.narvi.protego.CrudAction;
import app.narvi.protego.Permission;

public class TenantAccessPermission extends Permission<CrudAction, TenantResource> {

  public TenantAccessPermission(CrudAction action, TenantResource protectedResource) {
    super(action, protectedResource);
  }
}
