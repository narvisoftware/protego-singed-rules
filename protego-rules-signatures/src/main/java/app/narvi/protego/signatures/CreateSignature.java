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
import org.yaml.snakeyaml.events.MappingEndEvent;
import org.yaml.snakeyaml.events.MappingStartEvent;
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

    createSignature.getSignature("bibi");

  }

  private String getSignature(String stringToHashAndEncrypt) throws Exception {
    //gen sha-1
    MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
    sha1.reset();
    sha1.update(stringToHashAndEncrypt.getBytes(StandardCharsets.UTF_8));

    String hashString = Base64.getEncoder().encodeToString(sha1.digest());

//    System.out.println("string to hash = " + stringToHashAndEncrypt);
//    System.out.println("sha1 = " + hashString);

    //crypt sha-1
    byte[] privateKeyBytes = Files.readAllBytes(Paths.get("temp/key.pkcs8"));

    //for using in sources
    //byte[] privateKeyBytes = CreateSignature.class.getResourceAsStream("/key.pkcs8").readAllBytes();

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

//    System.out.println("decrypt = " + new String(decrypted, StandardCharsets.UTF_8));
//    System.out.println("*******\nencrypted signature (copy this):\n" + signature + "\n*******");

    return signature;

  }

  private void loadPublicKey() throws Exception {
    //decrypt
    byte[] pubKeyBytes = Files.readAllBytes(Paths.get("temp/publicKey.pub"));
    //for use in sources
    //byte[] pubKeyBytes = CreateSignature.class.getResourceAsStream("/publicKey.pub").readAllBytes();
    publicKeyString = new String(pubKeyBytes, StandardCharsets.UTF_8);
    publicKeyString = publicKeyString.replaceAll(NEW_LINE_CHARACTER, EMPTY_STRING)
        .replaceAll(PUBLIC_KEY_START_KEY_STRING, EMPTY_STRING)
        .replaceAll(PUBLIC_KEY_END_KEY_STRING, EMPTY_STRING)
        .replaceAll(NEW_CR_CHARACTER, EMPTY_STRING);

//    System.out.println("pubkey=" + publicKeyString);
  }

  private void addProtegoBasicToClasspath() throws Exception {

    URL url1 = newURL("./../target/classes");
//        URL url2 = newURL("./../src/main/resources");

    ClassLoader prevCl = Thread.currentThread().getContextClassLoader();
    ClassLoader urlCl = URLClassLoader.newInstance(new URL[]{url1}, prevCl);
    Thread.currentThread().setContextClassLoader(urlCl);

//        InputStream instr = urlCl.getResourceAsStream("protego-policy-rules-and-signatures.yml");
//        InputStream instr = urlCl.getResourceAsStream("protego-policy-rules-and-signatures.yml");
//        InputStreamReader strrd = new InputStreamReader(instr);
//        BufferedReader rr = new BufferedReader(strrd);
//
//        System.out.println(rr.lines().collect(Collectors.joining("\n")));

//        System.out.println("in str: " + instr);

    Class cl = Class.forName("app.narvi.authz.rules.BasicPolicyRuleProvider");
//    System.out.println(cl.getCanonicalName());

  }

  private void loadClasses() throws Exception {
    URL fileUrl = newURL("./../src/main/resources/protego-policy-rules-and-signatures.yml");
    JsonPath jsonPath = new JsonPath();
//        Yaml yaml = new Yaml();
//        FileReader contentFromFile = new FileReader(new File(fileUrl.toURI()));
//        for (Node node : yaml.composeAll(contentFromFile)) {
//
//        }
//
//        FileWriter fileWriter = new FileWriter(new File(fileUrl.toURI()));
//        Emitter emitter = new Emitter(fileWriter, new DumperOptions());
//        for (Event event : yaml.serialize(/* the root node */ node)) {
//            emitter.emit(event);
//        }
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
//        dumperOptions.setDefaultScalarStyle(ScalarStyle.LITERAL);
    //dumperOptions.setIndentWithIndicator(true);
//        dumperOptions.setExplicitEnd(true);
//        dumperOptions.setExplicitStart(true);

//        dumperOptions.setDefaultScalarStyle(ScalarStyle.PLAIN);
    Yaml yaml = new Yaml(new Constructor(loaderOptions), new Representer(dumperOptions), dumperOptions, loaderOptions);

    MappingNode root;
    try (FileReader reader = new FileReader(new File(fileUrl.toURI()))) {
      root = (MappingNode) yaml.compose(reader);
    }

    StringWriter generatedFile = new StringWriter();

    Writer writer = new PrintWriter(new BufferedWriter(generatedFile));
    Emitter emitter = new Emitter(/* e.g. a FileWriter */ writer, dumperOptions);
    boolean isPublicKeyValueEvent = false;
    boolean isPolycyRulesSequenceEvent = false;
    SignatureClass signatureForClass = null;
    String policyClass = null;
    for (Event event : yaml.serialize(/* the root node */ root)) {



      jsonPath.add(event);

      String pubKeyGlobal = jsonPath.receive("/public-key/val");
      String aClass = jsonPath.receive("/policy-rules/class/val");
      String aSignature = jsonPath.receive("/policy-rules/signature/val");

      if(pubKeyGlobal != null) {
        System.out.println("[PROGRAM] public key : " + pubKeyGlobal);
      }


      if(aClass != null) {
        signatureForClass = new SignatureClass();
        signatureForClass.className = aClass;
      }

      if(aSignature != null) {
        signatureForClass.signature = aSignature;
        System.out.println("[PROGRAM] signature : " + signatureForClass.className + " = " + signatureForClass.signature);
        signatureForClass = null;
      }







      if (event instanceof MappingStartEvent) {
        MappingStartEvent ev = (MappingStartEvent) event;
//                System.out.println("mark: " + (ev.getStartMark() == null ? "null" : ev.getStartMark().getName()));
//                System.out.println("mark: " + (ev.getEndMark() == null ? "null" : ev.getEndMark().getName()));
      }
      if (event instanceof MappingEndEvent) {
        MappingEndEvent ev = (MappingEndEvent) event;
//                System.out.println(event.getEventId() == ID.MappingEnd);
//                System.out.println(ev.getClass().getCanonicalName());
//                System.out.println("mark: " + (ev.getStartMark() == null ? "null" : ev.getStartMark().getName()));
//                System.out.println("mark: " + (ev.getEndMark() == null ? "null" : ev.getEndMark().getName()));
      }

      if (isPolycyRulesSequenceEvent && event.getEventId() == ID.SequenceEnd) {
        isPolycyRulesSequenceEvent = false;
      }

      if (event.getEventId() == ID.Scalar) {
        ScalarEvent ev = (ScalarEvent) event;
//         System.out.println("scalar val: " + ev.getValue());
        if (isPublicKeyValueEvent) {
          isPublicKeyValueEvent = false;
          event = new ScalarEvent(
              ev.getAnchor(),
              ev.getTag(),
              ev.getImplicit(),
              publicKeyString,
              ev.getStartMark(),
              ev.getEndMark(),
              ev.getScalarStyle());
        }
        if ("public-key".equals(ev.getValue())) {
          isPublicKeyValueEvent = true;
        }

        if ("signature".equals(ev.getValue())) {
          emitter.emit(event);
          continue;
        }

        if (policyClass != null && !policyClass.isEmpty() && isPolycyRulesSequenceEvent) {
          String signature = getSignature(policyClass);
          event = new ScalarEvent(
              ev.getAnchor(),
              ev.getTag(),
              ev.getImplicit(),
              signature,
              ev.getStartMark(),
              ev.getEndMark(),
              ev.getScalarStyle());
          policyClass = null;
        }

        if (policyClass != null && policyClass.isEmpty()) {
          policyClass = ev.getValue();
        }

        if (policyClass == null && isPolycyRulesSequenceEvent) {
          if ("class".equals(ev.getValue())) {
            policyClass = "";
          }
        }

        if ("policy-rules".equals(ev.getValue())) {
          isPolycyRulesSequenceEvent = true;
        }

      }
      emitter.emit(event);

    }

    FileWriter fileWriter = new FileWriter(new File(fileUrl.toURI()));
    generatedFile.flush();
    fileWriter.write(generatedFile.toString());
    fileWriter.close();

//
//        ScalarNode pubKeyNode = null;
//        SequenceNode policyRulesNode = null;
//        for(NodeTuple aNode : root.getValue()) {
//            if("public-key".equals(((ScalarNode)aNode.getKeyNode()).getValue())) {
//                pubKeyNode = (ScalarNode) aNode.getValueNode();
//            }
//            if("policy-rules".equals(((ScalarNode)aNode.getKeyNode()).getValue())) {
//                policyRulesNode = (SequenceNode) aNode.getValueNode();
//            }
//        }
//        if(policyRulesNode == null) {
//            throw new RuntimeException("Cannot find node \"policy-rules\" in " + fileUrl);
//        }
//        for(Node policyRules : policyRulesNode.getValue()) {
//            List<NodeTuple> policyRulesList = ((MappingNode) policyRules).getValue();
//            for(NodeTuple aPolicyRuleNode : policyRulesList) {
//                System.out.println("List: " + aPolicyRuleNode);
//                ((ScalarNode)aPolicyRuleNode.getValueNode()).
//            }
//
//        }
//
//
//        NodeTuple pubKeyTuple = root.getValue().get(0);
//        ScalarNode key = (ScalarNode) pubKeyTuple.getKeyNode();
//        ScalarNode val = (ScalarNode) pubKeyTuple.getValueNode();
//        System.out.println("val type: " + val.getType().getSimpleName());
//
//        NodeTuple pubKeyTuple2 = (NodeTuple)((MappingNode)root).getValue().get(1);
//        ScalarNode key2 = (ScalarNode) pubKeyTuple2.getKeyNode();
//        SequenceNode val2 = (SequenceNode) pubKeyTuple2.getValueNode();
//        System.out.println("val2 type: " + val2.getType().getSimpleName());
//
//
//        System.out.println("1. node: " + root.getClass().getSimpleName());
//        if (root instanceof MappingNode) {
//            MappingNode collectionNode = (MappingNode) root;
//            for(Object node : collectionNode.getValue()) {
//                System.out.println("x. node: " + node.getClass().getSimpleName());
//                if(node instanceof NodeTuple) {
//                    NodeTuple tuple = (NodeTuple) node;
//                    System.out.println("key: " + tuple.getKeyNode());
//                    System.out.println("val: " + tuple.getValueNode());
//                }
////                if(node instanceof ScalarNode) {
////                    System.out.println("scalar");
////                }
//                if(node instanceof CollectionNode) {
//                    System.out.println("collection");
//                    for(Object node2 : collectionNode.getValue()) {
//                        System.out.println("y. node: " + node2.getClass().getSimpleName());
//                    }
//                }
//            }
//        }
//
//        try (PrintWriter writer = new PrintWriter(System.out)) {
//            yaml.serialize(root, writer);
//        }



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
      ---------------------------------------|
      | push(e)	    | addFirst(e)           |
      | pop()	      | removeFirst()        |
      | peek()    	| peekFirst()           |
      ________________________________________
     */
    Deque<Event> pathEventsStack = new ArrayDeque() {};
    List<String> currentPath = new ArrayList<>();
    boolean isKeyValueEvent = false;
    boolean lastEventWasComment = false;

    public void add(Event event) {
      System.out.println("Recived Event :" + event.getEventId().name());
      if (event.getEventId() == ID.Comment) {
        lastEventWasComment  = true;
        return;
      }
      lastEventWasComment = false;

      if (event.getEventId().name().endsWith("End")) {
        String nameOfEvent = event.getEventId().name().substring(0, event.getEventId().name().lastIndexOf("End"));
        System.out.println("End Event: " + event.getEventId().name() + ", " + nameOfEvent);
        if (isKeyValueEvent) {
          isKeyValueEvent = false;
          pathEventsStack.removeFirst();
          pathEventsStack.removeFirst();
          currentPath.removeLast();
          currentPath.removeLast();
        }

        currentPath.removeLast();
        Event extracted = pathEventsStack.removeFirst();

        System.out.println("extracted from queue: " + extracted.getEventId().name());
        if (extracted == null) {
          throw new RuntimeException("End not match start. Queue is EMPTY");
        }
        if(extracted.getEventId() == ID.Scalar) {
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
        System.out.println("Scalar val: " + ((ScalarEvent) event).getValue());
        boolean isNextScalar = false;
        if (pathEventsStack.peekFirst().getEventId() == ID.Scalar && isKeyValueEvent == true) {
          isKeyValueEvent = false;
          isNextScalar = true;
          pathEventsStack.removeFirst();
          pathEventsStack.removeFirst();
          currentPath.removeLast();
          currentPath.removeLast();
        }
        if (pathEventsStack.peekFirst().getEventId() == ID.Scalar && !isNextScalar) {
          isKeyValueEvent = true;
          currentPath.add("val");
        } else {
          currentPath.add(((ScalarEvent) event).getValue());
        }
      } else {
        currentPath.add(event.getEventId().name());
      }


      pathEventsStack.addFirst(event);


      String path = "";
      for (String aPathEntry : currentPath) {
        path = path + "/" + aPathEntry;
      }
      String path2 = "";
      List pathEventsStack2 = new ArrayList(Arrays.asList(pathEventsStack.toArray()));
      Collections.reverse(pathEventsStack2);
      for (Event aPathEntry : (List<Event>)pathEventsStack2) {
        path2 = path2 + "/" + aPathEntry.getEventId().name();
      }

      System.out.println("CURRENT PATH = " + path);
      System.out.println("CURRENT EVENTS = " + path2);

    }


    public String receive(String path) {

      if(!path.endsWith("/val")) {
        throw new RuntimeException("You can query only for vals");
      }

      if(lastEventWasComment) {
        return null;
      }


      List extractedPathEventsStack = new ArrayList(Arrays.asList(pathEventsStack.toArray()));
      Collections.reverse(extractedPathEventsStack);

      String currrentPath = "";
      boolean previousIsVal = false;
      for (Event aPathEntry : (List<Event>)extractedPathEventsStack) {
        if(aPathEntry.getEventId() != ID.Scalar) {
          previousIsVal = false;
          continue;
        }
        if(previousIsVal) {
          previousIsVal = false;
          currrentPath += "/val";
          continue;
        }
        ScalarEvent scalar = (ScalarEvent)aPathEntry;
        currrentPath += ("/" + scalar.getValue());
        previousIsVal =true;
      }

      if(currrentPath.equals(path)) {
        return ((ScalarEvent)pathEventsStack.peekFirst()).getValue();
      } else {
        return null;
      }

//      System.out.println("CURRENT SCALARS PATH: " + currrentPath);
//      return currrentPath;
    }

  }


}
