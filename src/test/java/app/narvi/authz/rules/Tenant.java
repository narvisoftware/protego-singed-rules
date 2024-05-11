package app.narvi.authz.rules;

import java.util.UUID;

public class Tenant {
  private String id;
  private String name;

  public Tenant(String name) {
    this.name = name;
    id= UUID.randomUUID().toString().replaceAll("-", "");
  }
}