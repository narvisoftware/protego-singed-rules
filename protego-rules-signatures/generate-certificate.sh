#!/bin/bash

read -p "Do you want to regenerate the keys? (yes/no) " yn

case $yn in
	yes ) echo ok, generating...;;
	no ) echo exiting...;
		exit;;
	* ) echo invalid response;
		exit 1;;
esac

RUN_DIR=$(pwd)
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo Scrip is running in: $RUN_DIR
echo Script is located in: $SCRIPT_DIR

mkdir temp
cd temp

rm key.pem
rm key.pkcs8
rm publicKey.pub

openssl genrsa -out key.pem 512
openssl pkcs8 -topk8 -in key.pem -nocrypt -outform DER -out key.pkcs8
openssl rsa -in key.pem -pubout > publicKey.pub

cd ..