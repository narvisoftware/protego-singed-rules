package app.narvi.example;

import org.junit.jupiter.api.Test;

public class ExampleTest {


  @Test
  public void example1() {
    Tenant clinic = new Tenant("Bucharest Central Clinic");
    User patient = new User("John Doe", clinic);



    //PolicyEvaluator.evaluate();

  }

}