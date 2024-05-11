package app.narvi.authz.rules.allownothing;

import static app.narvi.authz.CrudAction.READ;

import app.narvi.authz.CrudAction;
import app.narvi.authz.Permission;
import app.narvi.authz.PolicyEvaluator;
import app.narvi.authz.PolicyException;
import app.narvi.authz.PolicyRulesProvider;
import app.narvi.authz.rules.BasicPolicyRuleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class AllowNothingTest {


  @Test
  public void denyAllTest() {
    PolicyRulesProvider policyRulesProvider = new BasicPolicyRuleProvider();
    PolicyEvaluator.registerProviders(policyRulesProvider);
    FakePermission dummyPermission = new FakePermission(READ, new Object());
    Throwable exception = Assertions.assertThrows(PolicyException.class,
        () -> PolicyEvaluator.evaluatePermission(dummyPermission));
    Assertions.assertEquals(PolicyException.class, exception.getClass());
  }

  public class FakePermission extends Permission {
    public FakePermission(CrudAction action, Object protectedResource) {
      super(action, protectedResource);
    }
  }

}