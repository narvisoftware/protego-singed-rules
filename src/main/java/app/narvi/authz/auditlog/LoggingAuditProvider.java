package app.narvi.authz.auditlog;

import java.lang.invoke.MethodHandles;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import app.narvi.authz.AuditProvider;
import app.narvi.authz.Permission;
import app.narvi.authz.PolicyRule;
import app.narvi.authz.SecurityContext;


public class LoggingAuditProvider implements AuditProvider {

  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  @Override
  public void audit(Permission permission, PolicyRule policyRule, SecurityContext securityContext) {

  }
}