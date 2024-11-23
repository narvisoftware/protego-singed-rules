package app.narvi.protego.signatures.rules.doctor;

import app.narvi.protego.signatures.rules.sametenant.Tenant;
import app.narvi.protego.signatures.rules.sametenant.User;

public class PatientFile {

  Tenant tenantClinic;
  User patient;
  String diagnosticHistory;

  public PatientFile(Tenant tenantClinic, User patient) {
    this.tenantClinic = tenantClinic;
    this.patient = patient;
  }
}