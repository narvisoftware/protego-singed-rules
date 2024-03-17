package app.narvi.authz.rules;

import java.nio.charset.StandardCharsets;

import app.narvi.authz.BasicPolicyRule;
import app.narvi.authz.PolicyRule;
import app.narvi.authz.PolicyRulesProvider;

public class NotApplicableRulesPolicy extends BasicPolicyRule {

  public String encryptedSha1() {
    return "u2u1L7i71V5NDyn+rAg2wcT5s/HBvGEf3Gg78QQH86uyjcN4LlwmaAzMNQqLH/Kn4CamjYLbo13vmTy5uN4rHQ==";
  }
}