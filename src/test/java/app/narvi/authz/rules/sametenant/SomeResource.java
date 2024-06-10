package app.narvi.authz.rules.sametenant;

public class SomeResource extends TenantResource {

  private String name;

  public SomeResource(String name, Tenant tenantOwner) {
    super(tenantOwner);
    this.name = name;
  }

}
