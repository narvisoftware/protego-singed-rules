package app.narvi.authz.rules;

import app.narvi.authz.PolicyRule;

public interface BasicPolicyRule extends PolicyRule {

  String signature();

}
