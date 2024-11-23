package app.narvi.protego.signatures.rules;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.junit.jupiter.api.Test;

public class TestExecutionSteps {

  @Test
  @Target({ElementType.METHOD})
  @Retention(RetentionPolicy.RUNTIME)
  public @interface Scenario {

    String value();

  }

  public static class TestSteps {

    public static void AND_GIVEN_(String message) {
      GIVEN_(message);
    }

    public static void GIVEN_(String message) {
    }

    public static void AND_WHEN_(String message) {
      WHEN_(message);
    }

    public static void WHEN_(String message) {
    }

    public static void AND_THEN_(String message) {
      THEN_(message);
    }

    public static void THEN_(String message) {
    }
  }

}
