#!/bin/bash

openssl genrsa -out key.pem 512
openssl pkcs8 -topk8 -in key.pem -nocrypt -outform DER -out key.pkcs8
openssl rsa -in key.pem -pubout > publicKey.pub