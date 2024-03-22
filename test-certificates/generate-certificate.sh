#!/bin/bash

read -p "Do you want to regenerate the keys? (yes/no) " yn

case $yn in
	yes ) echo ok, generating...;;
	no ) echo exiting...;
		exit;;
	* ) echo invalid response;
		exit 1;;
esac

rm key.pem
rm key.pkcs8
rm publicKey.pub

openssl genrsa -out key.pem 512
openssl pkcs8 -topk8 -in key.pem -nocrypt -outform DER -out key.pkcs8
openssl rsa -in key.pem -pubout > publicKey.pub
