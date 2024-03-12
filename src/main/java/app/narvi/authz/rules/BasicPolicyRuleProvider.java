package app.narvi.authz.rules;

import java.util.Arrays;
import java.util.List;

import app.narvi.authz.PolicyRule;
import app.narvi.authz.PolicyRulesProvider;

public class BasicPolicyRuleProvider implements PolicyRulesProvider {

  private final List<PolicyRulesProvider> rulesProviders = List.of(
      () -> Arrays.asList(
          new AllowOwnTenantAccess(),
          new EveryoneCanReadPublicCatalogs()
      )
  );

  @Override
  public Iterable<PolicyRule> collect() {
    return null;
  }


}
