package app.narvi.protego.signatures.auditlog;

import static app.narvi.protego.AuditProvider.Decision.PERMIT;

import java.lang.invoke.MethodHandles;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import app.narvi.protego.AuditProvider;
import app.narvi.protego.Permission;
import app.narvi.protego.PolicyRule;

public class SimpleLoggingAuditProvider implements AuditProvider {

  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  @Override
  public void audit(Permission permission, PolicyRule policyRule, Decision decision) {
    LOG.debug("Audit: Rule " + policyRule.getClass() + " result:" + decision.name() + " for " +
        permission.getClass().getSimpleName());
    if (decision == PERMIT) {
      LOG.info(permission.getAction() + " action attempt to " + permission.getProtectedResource());
    }
  }

}