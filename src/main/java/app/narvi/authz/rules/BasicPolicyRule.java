package app.narvi.authz.rules;

import app.narvi.authz.Action;
import app.narvi.authz.Permission;
import app.narvi.authz.PolicyRule;

public abstract class BasicPolicyRule<PR, A> implements PolicyRule {
  private Object protectedResource;
  private Action action;

  public BasicPolicyRule(Permission<PR, A> permission) {

  }
}