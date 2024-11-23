package app.narvi.protego.signatures.rules.conf;

public class SignatureUnmatchException extends RuntimeException {

  public SignatureUnmatchException(String message) {
    super(message);
  }

  public SignatureUnmatchException(String message, Throwable cause) {
    super(message, cause);
  }
}
