echo %*
IF "%~3" == "" ( set "ghSsl_repo=openssl" ) ELSE ( set "ghSsl_repo=%~3" )
IF "%~2" == "" ( set "ghSsl_user=DavidXanatos" ) ELSE ( set "ghSsl_user=%~2" )
IF "%~1" == "" ( set "openssl_version=3.3.0" ) ELSE ( set "openssl_version=%~1" )

IF "%openssl_version:~0,1%" == "1" set "openssl_version_underscore=%openssl_version:.=_%"

mkdir %~dp0\OpenSSL

IF "%openssl_version:~0,1%" == "1" (
curl -L --url https://github.com/%ghSsl_user%/%ghSsl_repo%/releases/download/OpenSSL_%openssl_version_underscore%/OpenSSL-%openssl_version_underscore%.zip -o %~dp0\OpenSSL\OpenSSL-%openssl_version%.zip --ssl-no-revoke
) ELSE (
curl -L --url https://github.com/%ghSsl_user%/%ghSsl_repo%/releases/download/openssl-%openssl_version%/openssl-%openssl_version%.zip -o %~dp0\OpenSSL\OpenSSL-%openssl_version%.zip --ssl-no-revoke
)

"C:\Program Files\7-Zip\7z.exe" x -bd -o%~dp0\OpenSSL\ %~dp0\OpenSSL\OpenSSL-%openssl_version%.zip

