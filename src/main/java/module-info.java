import app.narvi.authz.AuditProvider;
import app.narvi.protego.signatures.auditlog.LoggingAuditProvider;

module app.narvi.protego.basic {
  requires transitive app.narvi.protego.core;
  requires org.slf4j;
  requires org.javassist;
  requires org.yaml.snakeyaml;

  exports app.narvi.protego.signatures.rules;

  opens app.narvi.protego.signatures.rules.conf to org.yaml.snakeyaml;

  provides AuditProvider with LoggingAuditProvider;
}