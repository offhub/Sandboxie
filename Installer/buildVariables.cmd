@echo on

set "qt_version=5.15.16"
set "qt6_version=6.7.3"
set "openssl_version=3.4.0"
set "ghSsl_user=xanasoft"
set "ghSsl_repo=openssl-builds"
set "ghQtBuilds_user=xanasoft"
set "ghQtBuilds_repo=qt-builds"
set "ghQtBuilds_hash_x86=3ADC4017A200E93CB4B77498D8F9BB163D908B35B66D024588ED44AFEBE1C907"
set "ghQtBuilds_hash_x86_Qt6=E9084586DDE248E7D367A365A9DBB860303C31255DC0E63940213D3E3C008D45"
set "ghQtBuilds_hash_x64=1E281C42FB6EBD69E4E6F79C9D399F8325D11775B2ACF52E94BF97E5CB26BD04"
set "ghQtBuilds_hash_x64_Qt6=98E3AD2B678C83BC6622CBD10697A6FAA4052B4EF45FA72E90770B7EE54A1CC7"
set "msvc_version=2019"

REM catch build_qt6
set "allArgs=%*"
set "allArgsCatch=%allArgs:build_qt6=%"
if not "%~1" == "" (
    if not "%allArgs%" == "%allArgsCatch%" (
        set "qt_version=%qt6_version%"
        set "msvc_version=2022"
        set "ghQtBuilds_hash_x86=%ghQtBuilds_hash_x86_Qt6%"
        set "ghQtBuilds_hash_x64=%ghQtBuilds_hash_x64_Qt6%"
    ) else (
        set "qt_version=%qt_version%"
        set "msvc_version=2019"
        set "ghQtBuilds_hash_x86=%ghQtBuilds_hash_x86%"
        set "ghQtBuilds_hash_x64=%ghQtBuilds_hash_x64%"
    )
)
