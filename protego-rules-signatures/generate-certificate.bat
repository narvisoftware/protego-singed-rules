@echo off
setlocal

choice /C YN /N /M "Do you want to regenerate the keys? [Y/N]?"
if not errorlevel 2 if errorlevel 1 goto Continue
exit /B

:Continue
echo ok, generating ...

mkdir temp
cd temp

rm key.pem
rm key.pkcs8
rm publicKey.pub

openssl genrsa -out private.pem 512
openssl pkcs8 -topk8 -in private.pem -nocrypt -outform DER -out private-der.pkcs8
openssl rsa -in private.pem -pubout -outform PEM -out public.pem

cd ..
endlocal
