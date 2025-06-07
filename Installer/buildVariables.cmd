@echo on

set "qt_version=5.15.17"
set "qt6_version=6.7.3"
set "openssl_version=3.5.0"
set "ghSsl_user=offhub"
set "ghSsl_repo=openssl"
set "ghQtBuilds_user=offhub"
set "ghQtBuilds_repo=qt-sbie-builds"
set "ghQtBuilds_hash_x86=1C22BB5C058147E3684D301332B6AA85987A9C6DB34E20B52A0EBCA72BD93A92"
set "ghQtBuilds_hash_x64=AC662609B93E8C5A7160D4903F27AB5990DE468670ACEAEAA65FD6FA13BEB9B5"

REM catch build_qt6
set "allArgs=%*"
set "allArgsCatch=%allArgs:build_qt6=%"
if not "%~1" == "" (
    if not "%allArgs%" == "%allArgsCatch%" (
        set "qt_version=%qt6_version%"
    ) else (
        set "qt_version=%qt_version%"
    )
)
