package app.narvi.protego.signatures.rules.doctor;

import static app.narvi.protego.CrudAction.READ;

import app.narvi.protego.CrudAction;
import app.narvi.protego.Permission;
import app.narvi.protego.PolicyRule;
import app.narvi.protego.signatures.rules.sametenant.User;
import app.narvi.protego.signatures.rules.sametenant.User.Role;

public class AllowSameBranchPolicyRule implements PolicyRule {

  private static final ScopedValue<User> AUTHENTICATED_USER = ScopedValue.newInstance();

  @Override
  public boolean hasPermisssion(Permission permission) {
    if (!(permission instanceof AllowSameBranchPermission)) {
      return false;
    }
    //the doctor is the subject
    User authenticatedUser = AUTHENTICATED_USER.get();
    if (authenticatedUser.getRole() != Role.DOCTOR) {
      return false;
    }
    // only read is allowed
    if (permission.getAction() != READ) {
      return false;
    }
//    // has an appointment today
//    if (!permission.getProtectedResource().getOwner().hasAppointemnt(authenticatedUser, LocalDate.now())) {
//      return WITHHOLD;
//    }
//    //the medical record belongs to the same medicine branch
//    if (authenticatedUser.asDoctor().getSpeciality() != permission.getProtectedResource().getSpeciality()) {
//      return WITHHOLD;
//    }
//    //the doctor is at work
//    if (!authenticatedUser.getTodaysWorkingHoursInterval().includes(Instant.now())) {
//      return WITHHOLD;
//    }
//    return PERMIT;
    return true;
  }


}
