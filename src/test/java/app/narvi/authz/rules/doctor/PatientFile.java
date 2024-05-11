package app.narvi.authz.rules.doctor;

import app.narvi.authz.rules.allownothing.Tenant;
import app.narvi.authz.rules.allownothing.User;

public class PatientFile {
  Tenant tenantClinic;
  User patient;
  String diagnosticHistory;

  public PatientFile(Tenant tenantClinic, User patient) {
    this.tenantClinic = tenantClinic;
    this.patient = patient;
  }
}