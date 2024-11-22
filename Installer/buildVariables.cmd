@echo on

set "qt_version=6.8.0"
set "qt6_version=6.8.0"
set "openssl_version=3.4.0"
set "ghSsl_user=xanasoft"
set "ghSsl_repo=openssl-builds"
set "ghQtBuilds_user=offhub"
set "ghQtBuilds_repo=qt-sbie-builds"
set "ghQtBuilds_hash_x86=E9084586DDE248E7D367A365A9DBB860303C31255DC0E63940213D3E3C008D45"
set "ghQtBuilds_hash_x64=98E3AD2B678C83BC6622CBD10697A6FAA4052B4EF45FA72E90770B7EE54A1CC7"

REM catch build_qt6
set "allArgs=%*"
set "allArgs=%allArgs:build_qt6=%
if not "%*" == "%allArgs:build_qt6=%" (
    set "qt_version=%qt6_version%"
) else (
    set "qt_version=%qt_version%"
)
