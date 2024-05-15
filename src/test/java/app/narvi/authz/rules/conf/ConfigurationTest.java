package app.narvi.authz.rules.conf;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class ConfigurationTest {

  @Test
  void loadConfiguration() {
    Configuration conf = new Configuration();
    conf.setPublicKey("Dummy Key");
    conf.getPolicyRuleCofigurations()
        .add(
            new PolicyRuleCofiguration(
                "app.narvi.authz.rules.sametenant.AllowOwnTenantPolicyRule",
                "dummy signature")
        );
    Throwable exception = Assertions.assertThrows(
        SignatureUnmatchException.class,
        () -> conf.validateSignatures());
    Assertions.assertEquals(SignatureUnmatchException.class, exception.getClass());
  }
}