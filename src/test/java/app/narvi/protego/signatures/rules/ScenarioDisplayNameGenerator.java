package app.narvi.protego.signatures.rules;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.Set;

import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.platform.commons.util.ClassUtils;
import org.junit.platform.commons.util.Preconditions;

import app.narvi.protego.signatures.rules.TestExecutionSteps.Scenario;

public class ScenarioDisplayNameGenerator implements DisplayNameGenerator {

  private static Set<Method> executedTestMethods = new LinkedHashSet<>();

  @Override
  public String generateDisplayNameForClass(Class<?> testClass) {
    String name = testClass.getName();
    int lastDot = name.lastIndexOf('.');
    return name.substring(lastDot + 1);
  }

  @Override
  public String generateDisplayNameForNestedClass(Class<?> nestedClass) {
    return nestedClass.getSimpleName();
  }

  @Override
  public String generateDisplayNameForMethod(Class<?> testClass, Method testMethod) {
    Scenario scenarioAScenario = testMethod.getAnnotation(Scenario.class);
    if (scenarioAScenario == null) {
      return testMethod.getName() + parameterTypesAsString(testMethod);
    }
    Method[] testMethods = testClass.getDeclaredMethods();
    Arrays.sort(testMethods, new Comparator<Method>() {

      @Override
      public int compare(Method m1, Method m2) {
        return m1.toString().compareTo(m2.toString());
      }
    });
    int totalNumberOfMethods = 0;
    for (int a = 1; a <= testMethods.length; a++) {
      Method aMethod = testMethods[a - 1];
      if (aMethod.getAnnotation(Scenario.class) != null) {
        totalNumberOfMethods++;
      }
    }
    executedTestMethods.add(testMethod);
    return "[" + executedTestMethods.size() + " of " + totalNumberOfMethods + "]" +
        testMethod.getAnnotation(Scenario.class).value() +
        " (" + testMethod.getName() + "())";

  }

  static String parameterTypesAsString(Method method) {
    Preconditions.notNull(method, "Method must not be null");
    return '(' + ClassUtils.nullSafeToString(Class::getSimpleName, method.getParameterTypes()) + ')';
  }

}
