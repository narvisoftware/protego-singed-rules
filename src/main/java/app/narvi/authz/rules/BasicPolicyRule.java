package app.narvi.authz.rules;

import app.narvi.authz.PolicyRule;

interface BasicPolicyRule extends PolicyRule {

  String signature();

}
