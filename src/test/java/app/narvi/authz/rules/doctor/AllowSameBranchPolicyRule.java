package app.narvi.authz.rules.doctor;

import static app.narvi.authz.PolicyRule.Decision.PERMIT;
import static app.narvi.authz.PolicyRule.Decision.WITHHOLD;

import java.time.Instant;
import java.time.LocalDate;

import app.narvi.authz.CrudAction;
import app.narvi.authz.Permission;
import app.narvi.authz.PolicyRule;
import app.narvi.authz.rules.allownothing.User;

public class AllowSameBranchPolicyRule implements PolicyRule {

  private static final ScopedValue<User> AUTHENTICATED_USER = ScopedValue.newInstance();

  @Override
  public Decision evaluate(Permission permission) {
    if (!(permission instanceof AllowSameBranchPermission)) {
      return WITHHOLD;
    }
    //the doctor is the subject
    User authenticatedUser = AUTHENTICATED_USER.get();
    if (!authenticatedUser.isDoctor()) {
      return WITHHOLD;
    }
    // only read is allowed
    if (permission.getAction() != CrudAction.READ) {
      return WITHHOLD;
    }
    // has an appointment today
    if (!permission.getProtectedResource().getOwner().hasAppointemnt(authenticatedUser, LocalDate.now())) {
      return WITHHOLD;
    }
    //the medical record belongs to the same medicine branch
    if (authenticatedUser.asDoctor().getSpeciality() != permission.getProtectedResource().getSpeciality()) {
      return WITHHOLD;
    }
    //the doctor is at work
    if (!authenticatedUser.getTodaysWorkingHoursInterval().includes(Instant.now())) {
      return WITHHOLD;
    }
    return PERMIT;
  }
}
