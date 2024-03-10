package app.narvi.example;

import app.narvi.authz.Permission;
import app.narvi.authz.rules.BasicPolicyRule;

public class AllowOwnTenantAccess extends BasicPolicyRule {


  @Override
  public Decision evaluate(Permission permission) {
    return Decision.NOT_APPLICABLE;
  }

  public String getSignature() {
    return "fVSvJxxUR7MXujnPt/iPyr46/ZIh0KTIt94ZqEhvdekJ3s9H6FU05bNOVF325C6P2Me1tM71ssw4JeEfFI99IA==";
  }
}