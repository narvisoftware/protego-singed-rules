package app.narvi.authz.rules.sametenant;

import java.util.Objects;
import java.util.UUID;

public class SomeResource extends TenantResource{

  private String name;

  public SomeResource(String name, Tenant tenantOwner) {
    super(tenantOwner);
    this.name = name;
  }

}
