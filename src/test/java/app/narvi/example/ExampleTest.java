package app.narvi.example;

import app.narvi.authz.BasicPolicyRuleProvider;
import app.narvi.authz.Permission;
import app.narvi.authz.PolicyEvaluator;
import app.narvi.authz.PolicyException;
import app.narvi.authz.PolicyRulesProvider;
import app.narvi.authz.rules.AllowNothingPolicyRule;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ExampleTest {


  @Test
  public void example1() {
    PolicyRulesProvider policyRulesProvider = BasicPolicyRuleProvider.of(new AllowNothingPolicyRule(),
        new TestNotPermitRule());
    PolicyEvaluator.registerProviders(policyRulesProvider);
    FakePermission dummyPermission = new FakePermission(new Object(), new Object());
    Throwable exception = Assertions.assertThrows(PolicyException.class,
        () -> PolicyEvaluator.evaluatePermission(dummyPermission));
    Assertions.assertEquals(PolicyException.class, exception.getClass());
    //System.out.println(result);
  }

  public class FakePermission extends Permission {
    public FakePermission(Object protectedResource, Object action) {
      super(protectedResource, action);
    }
  }

}