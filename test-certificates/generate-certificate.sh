#!/bin/bash

read -p "Do you want to regenerate the keys? (yes/no) " yn

case $yn in
	yes ) echo ok, generating...;;
	no ) echo exiting...;
		exit;;
	* ) echo invalid response;
		exit 1;;
esac

#rm protego_keystore.jks
#rm publicKey.pem

# keytool -genkeypair -alias protegoKeyPair -keyalg RSA -keysize 512 \
#   -dname "CN=Narvi.app" -validity 365000 -storetype JKS \
#   -keystore protego_keystore.jks -storepass changeit -keypass keyPass
#
#keytool -exportcert -alias protegoKeyPair \
#  -keystore protego_keystore.jks \
#  -storetype jks -storepass changeit \
#  -rfc -file publicKey.pem

#openssl genrsa -out key.pem 512
#openssl rsa -in key.pem -outform PEM -pubout -out public.pem

# openssl genrsa -out keypair.pem 512
# openssl rsa -in keypair.pem -pubout -out publickey.crt
# openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key

openssl genrsa -out key.pem 512
openssl pkcs8 -topk8 -in key.pem -nocrypt -outform DER -out key.pkcs8
openssl rsa -in key.pem -pubout > publicKey.pub
