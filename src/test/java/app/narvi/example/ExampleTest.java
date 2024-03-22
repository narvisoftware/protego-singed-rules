package app.narvi.example;

import app.narvi.authz.BasicPolicyRuleProvider;
import app.narvi.authz.Permission;
import app.narvi.authz.PolicyEvaluator;
import app.narvi.authz.PolicyRule.Decision;
import app.narvi.authz.PolicyRulesProvider;
import app.narvi.authz.rules.AllowNothingPolicyRule;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import app.narvi.authz.PolicyException;

public class ExampleTest {


  @Test
  public void example1() {
    PolicyRulesProvider policyRulesProvider = BasicPolicyRuleProvider.of(new AllowNothingPolicyRule(), new TestNotPermitRule());
    PolicyEvaluator.registerProviders(policyRulesProvider);
    Throwable exception = Assertions.assertThrows(PolicyException.class,
        () -> PolicyEvaluator.evaluatePermission(new Permission(new Object(), new Object())));
    Assertions.assertEquals(PolicyException.class, exception.getClass());
    //System.out.println(result);
  }

}