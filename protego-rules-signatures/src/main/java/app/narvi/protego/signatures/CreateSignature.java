package app.narvi.protego.signatures;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Deque;
import java.util.List;
import javax.crypto.Cipher;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.DumperOptions.FlowStyle;
import org.yaml.snakeyaml.DumperOptions.LineBreak;
import org.yaml.snakeyaml.DumperOptions.NonPrintableStyle;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.emitter.Emitter;
import org.yaml.snakeyaml.events.Event;
import org.yaml.snakeyaml.events.Event.ID;
import org.yaml.snakeyaml.events.ScalarEvent;
import org.yaml.snakeyaml.nodes.MappingNode;
import org.yaml.snakeyaml.representer.Representer;

public class CreateSignature {

  public static final String NEW_LINE_CHARACTER = "\n";
  public static final String PUBLIC_KEY_START_KEY_STRING = "-----BEGIN PUBLIC KEY-----";
  public static final String PUBLIC_KEY_END_KEY_STRING = "-----END PUBLIC KEY-----";
  public static final String EMPTY_STRING = "";
  public static final String NEW_CR_CHARACTER = "\r";

  String publicKeyString;

  public static void main(String[] args) throws Exception {
    CreateSignature createSignature = new CreateSignature();
    createSignature.addProtegoBasicToClasspath();
    createSignature.loadPublicKey();
    createSignature.loadClasses();
  }

  private String getSignature(String stringToHashAndEncrypt) throws Exception {
    MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
    sha1.reset();
    sha1.update(stringToHashAndEncrypt.getBytes(StandardCharsets.UTF_8));

    String hashString = Base64.getEncoder().encodeToString(sha1.digest());

    byte[] privateKeyBytes = Files.readAllBytes(Paths.get("temp/key.pkcs8"));

    PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) kf.generatePrivate(privateKeySpec);

    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, rsaPrivateKey);
    byte[] encryptedMessageHash = cipher.doFinal(hashString.getBytes(StandardCharsets.UTF_8));

    byte[] decoded = Base64
        .getDecoder()
        .decode(publicKeyString);

    KeySpec keySpec = new X509EncodedKeySpec(decoded);

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PublicKey publicKey = keyFactory.generatePublic(keySpec);

    final Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher2.init(Cipher.DECRYPT_MODE, publicKey);

    byte[] decrypted = cipher2.doFinal(encryptedMessageHash);
    String signature = Base64.getEncoder().encodeToString(encryptedMessageHash);

    System.out.println("*******\nencrypted signature:\n" + signature + "\n*******");

    return signature;
  }

  private void loadPublicKey() throws Exception {
    byte[] pubKeyBytes = Files.readAllBytes(Paths.get("temp/publicKey.pub"));
    publicKeyString = new String(pubKeyBytes, StandardCharsets.UTF_8);
    publicKeyString = publicKeyString.replaceAll(NEW_LINE_CHARACTER, EMPTY_STRING)
        .replaceAll(PUBLIC_KEY_START_KEY_STRING, EMPTY_STRING)
        .replaceAll(PUBLIC_KEY_END_KEY_STRING, EMPTY_STRING)
        .replaceAll(NEW_CR_CHARACTER, EMPTY_STRING);
  }

  private void addProtegoBasicToClasspath() throws Exception {
    URL url1 = newURL("./../target/classes");
    ClassLoader prevCl = Thread.currentThread().getContextClassLoader();
    ClassLoader urlCl = URLClassLoader.newInstance(new URL[]{url1}, prevCl);
    Thread.currentThread().setContextClassLoader(urlCl);
  }

  private void loadClasses() throws Exception {
    LoaderOptions loaderOptions = new LoaderOptions();
    loaderOptions.setProcessComments(true);

    DumperOptions dumperOptions = new DumperOptions();
    dumperOptions.setProcessComments(true);
    dumperOptions.setIndent(2);
    dumperOptions.setLineBreak(LineBreak.UNIX);
    dumperOptions.setNonPrintableStyle(NonPrintableStyle.ESCAPE);
    dumperOptions.setIndentWithIndicator(true);
    dumperOptions.setDefaultFlowStyle(FlowStyle.BLOCK);
    dumperOptions.setPrettyFlow(true);
    dumperOptions.setSplitLines(false);

    Yaml yaml = new Yaml(new Constructor(loaderOptions), new Representer(dumperOptions), dumperOptions, loaderOptions);

    URL fileUrl = newURL("./../src/main/resources/protego-policy-rules-and-signatures.yml");
    MappingNode root;
    try (FileReader reader = new FileReader(new File(fileUrl.toURI()))) {
      root = (MappingNode) yaml.compose(reader);
    }

    StringWriter generatedFile = new StringWriter();
    Writer writer = new PrintWriter(new BufferedWriter(generatedFile));
    Emitter emitter = new Emitter(writer, dumperOptions);

    SignatureClass signatureForClass = null;
    JsonPath jsonPath = new JsonPath();
    for (Event event : yaml.serialize(root)) {

      jsonPath.add(event);

      String pubKeyGlobal = jsonPath.receive("/public-key/val");
      String aClass = jsonPath.receive("/policy-rules/class/val");
      String aSignature = jsonPath.receive("/policy-rules/signature/val");

      if (pubKeyGlobal != null) {
        ScalarEvent scalarEv = (ScalarEvent) event;
        event = new ScalarEvent(
            scalarEv.getAnchor(),
            scalarEv.getTag(),
            scalarEv.getImplicit(),
            publicKeyString,
            scalarEv.getStartMark(),
            scalarEv.getEndMark(),
            scalarEv.getScalarStyle());
      }

      if (aClass != null) {
        signatureForClass = new SignatureClass();
        signatureForClass.className = aClass;
      }

      if (aSignature != null) {
        signatureForClass.signature = aSignature;
        String signature = getSignature(signatureForClass.className);
        ScalarEvent scalarEv = (ScalarEvent) event;
        event = new ScalarEvent(
            scalarEv.getAnchor(),
            scalarEv.getTag(),
            scalarEv.getImplicit(),
            signature,
            scalarEv.getStartMark(),
            scalarEv.getEndMark(),
            scalarEv.getScalarStyle());
        signatureForClass = null;
      }

      emitter.emit(event);
    }

    FileWriter fileWriter = new FileWriter(new File(fileUrl.toURI()));
    generatedFile.flush();
    fileWriter.write(generatedFile.toString());
    fileWriter.close();
  }

  private URL newURL(String relativePath) throws Exception {
    String absolutePath = FileSystems.getDefault().getPath(relativePath).toAbsolutePath().normalize().toString();
    return new URL("file:///" + absolutePath);
  }


  public static class SignatureClass {
    public String className;
    public String signature;
  }

  public static class JsonPath {
    /*
      Stack interface:
      _______________________________________
      |Stack Method | Equivalent Deque Method|
      |--------------------------------------|
      | push(e)	    | addFirst(e)            |
      | pop()	      | removeFirst()          |
      | peek()    	| peekFirst()            |
      ________________________________________
     */
    Deque<Event> pathEventsStack = new ArrayDeque() {};
    boolean isKeyValueEvent = false;
    boolean lastEventWasComment = false;

    public void add(Event event) {
      if (event.getEventId() == ID.Comment) {
        lastEventWasComment = true;
        return;
      }
      lastEventWasComment = false;

      if (event.getEventId().name().endsWith("End")) {
        String nameOfEvent = event.getEventId().name().substring(0, event.getEventId().name().lastIndexOf("End"));
        if (isKeyValueEvent) {
          isKeyValueEvent = false;
          pathEventsStack.removeFirst();
          pathEventsStack.removeFirst();
        }

        Event extracted = pathEventsStack.removeFirst();

        if (extracted == null) {
          throw new RuntimeException("End not match start. Queue is EMPTY");
        }
        if (extracted.getEventId() == ID.Scalar) {
          add(event);
          return;
        }
        int lastIndexOfStart = extracted.getEventId().name().lastIndexOf("Start");
        if (lastIndexOfStart == -1) {
          throw new RuntimeException(
              "End event not match start: " + event.getEventId().name() + " != " + extracted.getEventId().name());
        }
        String extractedName = extracted.getEventId().name().substring(0, lastIndexOfStart);
        if (!nameOfEvent.equals(extractedName)) {
          throw new RuntimeException("End event not match start: " + nameOfEvent + " != " + extractedName);
        }
        return;
      }

      if (event.getEventId() == ID.Scalar) {
        boolean isNextScalar = false;
        if (pathEventsStack.peekFirst().getEventId() == ID.Scalar && isKeyValueEvent == true) {
          isKeyValueEvent = false;
          isNextScalar = true;
          pathEventsStack.removeFirst();
          pathEventsStack.removeFirst();
        }
        if (pathEventsStack.peekFirst().getEventId() == ID.Scalar && !isNextScalar) {
          isKeyValueEvent = true;
        }
      }

      pathEventsStack.addFirst(event);
    }


    public String receive(String path) {

      if (!path.endsWith("/val")) {
        throw new RuntimeException("You can query only for vals");
      }

      if (lastEventWasComment) {
        return null;
      }

      List extractedPathEventsStack = new ArrayList(Arrays.asList(pathEventsStack.toArray()));
      Collections.reverse(extractedPathEventsStack);

      String currrentPath = "";
      boolean previousIsVal = false;
      for (Event aPathEntry : (List<Event>) extractedPathEventsStack) {
        if (aPathEntry.getEventId() != ID.Scalar) {
          previousIsVal = false;
          continue;
        }
        if (previousIsVal) {
          previousIsVal = false;
          currrentPath += "/val";
          continue;
        }
        ScalarEvent scalar = (ScalarEvent) aPathEntry;
        currrentPath += ("/" + scalar.getValue());
        previousIsVal = true;
      }

      if (currrentPath.equals(path)) {
        return ((ScalarEvent) pathEventsStack.peekFirst()).getValue();
      } else {
        return null;
      }
    }

  }


}
