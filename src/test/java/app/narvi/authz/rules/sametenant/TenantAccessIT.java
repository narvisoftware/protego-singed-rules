package app.narvi.authz.rules.sametenant;

import static app.narvi.authz.CrudAction.UPDATE;
import static app.narvi.authz.rules.conf.Configuration.FILE_NAME_PROPERTY;
import static app.narvi.authz.rules.sametenant.User.Role.PATIENT;
import static app.narvi.authz.rules.TestExecutionSteps.TestSteps.AND_GIVEN_;
import static app.narvi.authz.rules.TestExecutionSteps.TestSteps.GIVEN_;
import static app.narvi.authz.rules.TestExecutionSteps.TestSteps.WHEN_;

import app.narvi.authz.PolicyEvaluator;
import app.narvi.authz.PolicyRulesProvider;
import app.narvi.authz.rules.BasicPolicyRuleProvider;
import app.narvi.authz.rules.Test;
import app.narvi.authz.rules.TestExecutionSteps.Scenario;
import org.junit.jupiter.api.Assertions;

public class TenantAccessIT extends Test {

  @Scenario("User can have full access to his own tenant resources.")
  public void allowOwnTenant() {
    GIVEN_("Using cutom policy rules configuration file.");
    System.setProperty(FILE_NAME_PROPERTY, "app/narvi/authz/rules/sametenant/allow-same-tenant-policy-rules.yaml");

    AND_GIVEN_("The framework is initialized");
    PolicyRulesProvider policyRulesProvider = new BasicPolicyRuleProvider();
    PolicyEvaluator.registerProviders(policyRulesProvider);

    AND_GIVEN_("The user is authenticated");
    Tenant tenant = new Tenant("Sample Tenant");
    User user = new User("John Doe", PATIENT, tenant);

    ScopedValue.where(User.AUTHENTICATED_USER, user).run(() -> {

      AND_GIVEN_("The user and resource has the same tenant");
      SomeResource someResource = new SomeResource("Test Resource", tenant);

      WHEN_("User tests access to resource");
      TenantAccessPermission tenantAccessPermission = new TenantAccessPermission(UPDATE, someResource);
      PolicyEvaluator.evaluatePermission(tenantAccessPermission);
      Assertions.assertTrue(PolicyEvaluator.hasPermission(tenantAccessPermission));
    });
  }

  public void denyOtherTenant() {
//    Throwable exception = Assertions.assertThrows(PolicyException.class,
//        () -> PolicyEvaluator.evaluatePermission(dummyPermission));
//    Assertions.assertEquals(PolicyException.class, exception.getClass());
  }

}