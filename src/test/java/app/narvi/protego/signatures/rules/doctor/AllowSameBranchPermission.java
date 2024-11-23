package app.narvi.protego.signatures.rules.doctor;

import app.narvi.authz.Permission;

public class AllowSameBranchPermission<CrudAction, PacientRecord> extends Permission {


  public AllowSameBranchPermission(Object action, Object protectedResource) {
    super(action, protectedResource);
  }

}


