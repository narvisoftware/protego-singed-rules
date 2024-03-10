package app.narvi.example;

import app.narvi.authz.Permission;
import app.narvi.authz.rules.BasicPolicyRule;

public class EveryoneCanReadPublicCatalogs extends BasicPolicyRule {

  @Override
  public Decision evaluate(Permission permission) {
    return Decision.NOT_APPLICABLE;
  }

  public String getSignature() {
    return "HNZV4cw1uuUtqWvrXrL3N13qSzVG9YIXz1nWH8+7HL7QoIbVBOPpdu4rYgTYEtAcsLnXO2M2JOPD1eAg4bjYmA==";
  }
}