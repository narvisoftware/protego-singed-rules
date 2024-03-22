package app.narvi.authz.rules;

import static app.narvi.authz.PolicyRule.Decision.NOT_APPLICABLE;

import app.narvi.authz.Permission;

public class AllowNothingPolicyRule implements BasicPolicyRule {

  @Override
  public Decision evaluate(Permission permission) {
    return NOT_APPLICABLE;
  }

  @Override
  public String signature() {
    return "uEvgAOiPHJRfV2hbLBEg2oYqEG/SCMbD22IZCOLjcbmhvle0geGfLuTBbR0C2hfNuix9NFzbRLv8mXQzyvVUqQ==";
  }

}
