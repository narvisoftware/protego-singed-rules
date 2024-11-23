package app.narvi.protego.signatures.rules.sametenant;

import java.util.Objects;
import java.util.UUID;

public class Tenant {

  private String id;
  private String name;

  public Tenant(String name) {
    this.name = name;
    id = UUID.randomUUID().toString().replaceAll("-", "");
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Tenant tenant = (Tenant) o;
    return Objects.equals(id, tenant.id);
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(id);
  }
}