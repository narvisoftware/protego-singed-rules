package app.narvi.protego.signatures.rules.sametenant;

import java.util.Objects;
import java.util.UUID;

public class User {

  public static final ScopedValue<User> AUTHENTICATED_USER = ScopedValue.newInstance();

  private String id;
  private String name;
  private Role role;
  private Tenant tenantOwner;

  public enum Role {
    PATIENT,
    DOCTOR
  }

  public User(String name, Role role, Tenant tenantOwner) {
    this.name = name;
    this.role = role;
    this.tenantOwner = tenantOwner;
    id = UUID.randomUUID().toString().replaceAll("-", "");
  }

  public String getId() {
    return id;
  }

  public String getName() {
    return name;
  }

  public Role getRole() {
    return role;
  }

  public Tenant getTenantOwner() {
    return tenantOwner;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    User user = (User) o;
    return Objects.equals(id, user.id);
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(id);
  }
}