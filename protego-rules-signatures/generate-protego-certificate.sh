#!/bin/bash

# set -x

read -p "Do you want to regenerate the keys? (yes/no) " yn

case $yn in
	yes ) echo ok, generating...;;
	no ) echo exiting...;
		exit;;
	* ) echo invalid response;
		exit 1;;
esac

mkdir temp
cd temp

del /f key.pem
del /f key.pkcs8
del /f publicKey.pub

openssl genrsa -out private.pem 512
openssl pkcs8 -topk8 -in private.pem -nocrypt -outform DER -out private-der.pkcs8
openssl rsa -in private.pem -pubout -outform PEM -out public.pem

cd ..