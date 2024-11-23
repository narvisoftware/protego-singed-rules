package app.narvi.protego.signatures.rules.sametenant;

import java.util.Objects;
import java.util.UUID;

public class TenantResource {

  private String id;
  private Tenant tenantOwner;

  public TenantResource(Tenant tenantOwner) {
    this.tenantOwner = tenantOwner;
    id = UUID.randomUUID().toString().replaceAll("-", "");
  }

  public String getId() {
    return id;
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
    TenantResource that = (TenantResource) o;
    return Objects.equals(id, that.id);
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(id);
  }
}
