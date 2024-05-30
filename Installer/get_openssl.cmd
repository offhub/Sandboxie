set version=3.3.0

mkdir %~dp0\OpenSSL
curl -L --url https://github.com/offhub/openssl/releases/download/OpenSSL_%version%/OpenSSL-%version%.zip -o %~dp0\OpenSSL\OpenSSL-%version%.zip --ssl-no-revoke
"C:\Program Files\7-Zip\7z.exe" x -bd -o%~dp0\OpenSSL\ %~dp0\OpenSSL\OpenSSL-%version%.zip

