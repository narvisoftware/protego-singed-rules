package app.narvi.authz.auditlog;

import java.lang.invoke.MethodHandles;

import app.narvi.authz.AuditProvider;
import app.narvi.authz.Permission;
import app.narvi.authz.PolicyRule;
import app.narvi.authz.PolicyRule.Decision;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class LoggingAuditProvider implements AuditProvider {

  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  @Override
  public void audit(Permission permission, PolicyRule policyRule, Decision decision) {
    LOG.info("Audit: Rule " + policyRule.getClass() + " result:" + decision.name() + " for " + permission.getClass()
        .getSimpleName());
  }

}