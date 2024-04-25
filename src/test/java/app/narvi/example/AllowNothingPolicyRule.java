package app.narvi.example;

import static app.narvi.authz.PolicyRule.Decision.NOT_APPLICABLE;

import app.narvi.authz.Permission;
import app.narvi.authz.rules.BasicPolicyRule;

public class AllowNothingPolicyRule implements BasicPolicyRule {

  @Override
  public Decision evaluate(Permission permission) {
    return NOT_APPLICABLE;
  }

  @Override
  public String signature() {
    return "RWETxBl+QW/RwnC2a6ajNXivN9Id6QFzZYstY5jErCA53TFIIFMQZxTUFj8RNU5yfBvaAkAnwGsN/x5PxvQxdQ==";
  }

}
