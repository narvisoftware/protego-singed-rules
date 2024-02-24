#!/bin/bash

rm protego_keystore.jks
rm publicKey.pem
rm SignFile.class

keytool -genkeypair -alias protegoKeyPair -keyalg RSA -keysize 2048 \
  -dname "CN=Narvi.app" -validity 365000 -storetype JKS \
  -keystore protego_keystore.jks -storepass changeit -keypass keyPass

keytool -exportcert -alias protegoKeyPair \
  -keystore protego_keystore.jks \
  -storetype jks -alias protegoKeyPair -storepass changeit \
  -rfc -file publicKey.pem

javac SignFile.java
java SignFile