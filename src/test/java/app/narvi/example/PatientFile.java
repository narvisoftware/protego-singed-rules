package app.narvi.example;

public class PatientFile {
  Tenant tenantClinic;
  User patient;
  String diagnosticHistory;

  public PatientFile(Tenant tenantClinic, User patient) {
    this.tenantClinic = tenantClinic;
    this.patient = patient;
  }
}