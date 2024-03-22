package app.narvi.authz.rules;

import app.narvi.authz.Permission;

public class AllowNothingPolicyRule extends PolicyRule {

  @Override
  public Decision evaluate(Permission permission) {
    return null;
  }

  @Override
  public String signature() {
    return "u2u1L7i71V5NDyn+rAg2wcT5s/HBvGEf3Gg78QQH86uyjcN4LlwmaAzMNQqLH/Kn4CamjYLbo13vmTy5uN4rHQ==";
  }

}
