package app.narvi.authz.auditlog;

import static app.narvi.authz.AuditProvider.Decision.PERMIT;

import java.lang.invoke.MethodHandles;

import app.narvi.authz.AuditProvider;
import app.narvi.authz.Permission;
import app.narvi.authz.PolicyRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class LoggingAuditProvider implements AuditProvider {

  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  @Override
  public void audit(Permission permission, PolicyRule policyRule, Decision decision) {
    LOG.debug(STR."Audit: Rule \{policyRule.getClass()} result:\{decision.name()} for \{
        permission.getClass().getSimpleName()}");
    if(decision == PERMIT) {
      LOG.info(STR."\{permission.getAction()} action attempt to \{permission.getProtectedResource()}");
    }
  }

}