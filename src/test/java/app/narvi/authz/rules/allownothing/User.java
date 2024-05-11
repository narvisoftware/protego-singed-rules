package app.narvi.authz.rules.allownothing;

import java.util.UUID;

public class User {

  private String id;
  private String name;
  private Tenant tenantOwner;

  public User(String name, Tenant tenantOwner) {
    this.name = name;
    this.tenantOwner = tenantOwner;
    id= UUID.randomUUID().toString().replaceAll("-", "");
  }
}