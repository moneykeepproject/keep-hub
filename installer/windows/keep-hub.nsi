; Keep Hub's Windows setup: the hub's own release package, which keep-launcher installs and
; updates (docs/specs/keep-hub.md, "How the hub gets onto the computer"). It can also be run
; directly, without internet: it is the same file.
;
; Built by `cargo xtask installer` (xtask/src/installer.rs), which builds the program, puts it
; with the licence files in dist\keep-hub-<version>, and calls makensis with:
;   -DVERSION=0.1.0-alpha.1     the version (semver)
;   -DVERSION_QUAD=0.1.0.1      four numbers for Windows file versions
;   -DVERSION_ORDER=0.1.0.1.1   dotted numbers that compare in semver order
;                               (major.minor.patch.stage.number; stage 0 dev, 1 alpha, 2 beta,
;                               3 rc, 9 a release), for the upgrade check
;   -DSOURCE_DIR=<folder>       keep-hub.exe, licence.txt, the licences
;   -DOUT_FILE=<file>           dist\keep-hub-<version>-windows-x64-setup.exe (the name
;                               keep-launcher installs)
;
; Adapted from ShareKeep's setup (installer/windows/sharekeep.nsi), itself modelled on
; MoneyKeep's; written from the NSIS documentation (MUI2, LogicLib, x64.nsh, FileFunc.nsh,
; WordFunc.nsh). No PowerShell anywhere: sc.exe and net.exe, and the hub program's own
; `install-service`, `remove-service` and `registered-apps` (which use sc.exe, icacls.exe and
; netsh.exe).
;
; What it does:
; - per-machine install in C:\Program Files\Keep Hub, with administrator approval (the hub is
;   a service, run from where ordinary programs can't change it); no folder page;
; - pages: welcome (which version is installed or updated), licence, progress, finish; the
;   hub has no window, so there is nothing to open;
; - a version older than the one installed is refused: a hub is never replaced by an older
;   version (acceptance test 26);
; - updating: the hub is stopped, replaced and started again (phones see app_stopped for the
;   gap and retry); the hub's name, certificates and pairings are kept;
; - `keep-hub install-service`: the data folder %ProgramData%\Keep Hub (made the first time,
;   locked to the service and administrators, the computer's users may read admin.token), the
;   service under its own virtual account, the firewall rule "Keep Hub";
; - registers in Windows "Installed apps" (name, version and its order, publisher, size,
;   location, the uninstaller and its silent form);
; - the uninstaller: when apps still use the hub it names them and asks again (acceptance
;   test 25); it removes the service, the firewall rule, the program and the registration;
;   the data folder stays unless the person also chooses to delete it, so installing again
;   keeps the hub's name and pairings.
;
; Silent mode (/S, as keep-launcher runs it): no pages and no questions. Exit codes:
;   0 done
;   3 anything else stopped it (the setup's log says what)
;   4 a newer Keep Hub is installed: nothing was changed
;   5 (uninstall) apps still use the hub: nothing was removed. keep-launcher asks the person
;     itself, then runs the uninstaller again with /FORCE.
; /DELETEDATA (uninstall) deletes the data folder too.

Unicode true
ManifestDPIAware true
SetCompressor /SOLID lzma

!macro REQUIRE name
  !ifndef ${name}
    !error "${name} is not set: run cargo xtask installer (it passes VERSION, VERSION_QUAD, VERSION_ORDER, SOURCE_DIR and OUT_FILE)."
  !endif
!macroend
!insertmacro REQUIRE VERSION
!insertmacro REQUIRE VERSION_QUAD
!insertmacro REQUIRE VERSION_ORDER
!insertmacro REQUIRE SOURCE_DIR
!insertmacro REQUIRE OUT_FILE

; ----- names shared with Keep Hub's code ----------------------------------------------------------

!define PRODUCT "Keep Hub"
!define PUBLISHER "MoneyKeep Project"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\Keep Hub"
; keep-hub's service.rs: SERVICE_NAME and DATA_DIR
!define SERVICE "KeepHub"
!define HUB_DATA_DIR "Keep Hub"
!define HUB_EXE "keep-hub.exe"
; silent mode's exit codes besides 0 (keep-launcher reads them)
!define EXIT_FAILED 3
!define EXIT_NEWER_INSTALLED 4
!define EXIT_APPS_REGISTERED 5

; ----- the setup program --------------------------------------------------------------------------

Name "${PRODUCT}"
OutFile "${OUT_FILE}"
InstallDir "$PROGRAMFILES64\${PRODUCT}"
RequestExecutionLevel admin
BrandingText "${PRODUCT} ${VERSION} — MoneyKeep family"

VIProductVersion "${VERSION_QUAD}"
VIFileVersion "${VERSION_QUAD}"
VIAddVersionKey "ProductName" "${PRODUCT}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "CompanyName" "${PUBLISHER}"
VIAddVersionKey "FileDescription" "${PRODUCT} Setup"
VIAddVersionKey "LegalCopyright" "Copyright (c) 2026 MoneyKeep Project contributors (MIT OR Apache-2.0)"

!include MUI2.nsh
!include LogicLib.nsh
!include x64.nsh
!include FileFunc.nsh
!include WordFunc.nsh

Var OldVersion      ; the installed version, "" when none
Var OldOrder        ; its VERSION_ORDER
Var WelcomeText
Var HubData         ; %ProgramData%\Keep Hub
Var Apps            ; the apps that still use the hub (uninstall)
Var DeleteData      ; 1: the uninstaller deletes the data folder too
Var Haystack        ; Contains: is $Needle in $Haystack? -> $Found (1 or 0)
Var Needle
Var Found

!define MUI_ABORTWARNING

; ----- pages --------------------------------------------------------------------------------------

!define MUI_WELCOMEPAGE_TITLE "${PRODUCT} ${VERSION}"
!define MUI_WELCOMEPAGE_TEXT "$WelcomeText"
!insertmacro MUI_PAGE_WELCOME

; the licence (NOTICE: MIT OR Apache-2.0); nothing to agree to, so the button is Next
!define MUI_LICENSEPAGE_TEXT_TOP "Keep Hub is free software: use it under the MIT or the Apache 2.0 licence, at your option."
!define MUI_LICENSEPAGE_TEXT_BOTTOM "The full licences are installed with Keep Hub (LICENSE-MIT, LICENSE-APACHE, THIRD-PARTY-LICENSES.txt)."
!define MUI_LICENSEPAGE_BUTTON "$(^NextBtn)"
!insertmacro MUI_PAGE_LICENSE "${SOURCE_DIR}\licence.txt"

!insertmacro MUI_PAGE_INSTFILES

!define MUI_FINISHPAGE_TEXT "${PRODUCT} ${VERSION} is running. It has no window: go back to the app you were turning phones on in, and it carries on."
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; ----- helpers (each for Setup and, with the un. prefix, for the uninstaller) ---------------------

; $Found = 1 when $Needle occurs in $Haystack, else 0.
!macro CONTAINS_FN un
Function ${un}Contains
  StrCpy $Found 0
  StrLen $R1 $Needle
  StrCpy $R2 0
  ${Do}
    StrCpy $R3 $Haystack $R1 $R2
    ${If} $R3 == ""
      ${Break}
    ${EndIf}
    ${If} $R3 == $Needle
      StrCpy $Found 1
      ${Break}
    ${EndIf}
    IntOp $R2 $R2 + 1
  ${Loop}
FunctionEnd
!macroend
!insertmacro CONTAINS_FN ""
!insertmacro CONTAINS_FN "un."

; Stop the hub service when it runs (net stop waits until it has stopped), so its program can
; be replaced or removed.
!macro STOP_HUB_FN un
Function ${un}StopHub
  nsExec::ExecToStack `"$SYSDIR\sc.exe" query ${SERVICE}`
  Pop $0
  Pop $Haystack
  StrCpy $Needle "RUNNING"
  Call ${un}Contains
  ${If} $Found == 1
    DetailPrint "Stopping Keep Hub"
    nsExec::ExecToLog `"$SYSDIR\net.exe" stop ${SERVICE}`
    Pop $0
    Sleep 1000 ; the process lets go of its program file
  ${EndIf}
FunctionEnd
!macroend
!insertmacro STOP_HUB_FN ""
!insertmacro STOP_HUB_FN "un."

; ----- Setup --------------------------------------------------------------------------------------

Section "Keep Hub" SecMain
  SectionIn RO
  Call StopHub

  SetOutPath "$INSTDIR"
  File "${SOURCE_DIR}\${HUB_EXE}"
  File "${SOURCE_DIR}\LICENSE-MIT"
  File "${SOURCE_DIR}\LICENSE-APACHE"
  File "${SOURCE_DIR}\NOTICE"
  ; every crate compiled into the program with its licence (xtask/src/licences.rs)
  File "${SOURCE_DIR}\THIRD-PARTY-LICENSES.txt"

  ; Windows "Installed apps" (before the service, so a failed step can still be removed)
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayName" "${PRODUCT}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "VersionOrder" "${VERSION_ORDER}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "Comments" "Lets the household's phones reach the Keep and Pick apps on this computer."
  WriteRegStr HKLM "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNINSTALL_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "EstimatedSize" "$0"

  ; the data folder (the first time), the service, the folder's permissions, the firewall rule:
  ; one program, so the steps can't drift apart. Exit codes: keep_hub::service::Exit.
  DetailPrint "Setting up Keep Hub"
  nsExec::ExecToLog `"$INSTDIR\${HUB_EXE}" install-service`
  Pop $1
  ${If} $1 == 0
    Goto hubok
  ${ElseIf} $1 == 11
    StrCpy $6 "A folder named $HubData is there that Keep Hub's setup didn't make, and it can't be moved aside. The details are in the list above. Move or delete it, then run this setup again."
  ${ElseIf} $1 == 12
    StrCpy $6 "Keep Hub couldn't be set up: this computer isn't on a home network. Connect it to the home Wi-Fi or network, then run this setup again."
  ${ElseIf} $1 == 14
    StrCpy $6 "The Keep Hub service couldn't be started. The details are in the list above; $HubData\hub.log may say more."
  ${Else}
    StrCpy $6 "Keep Hub couldn't be set up (code $1). The details are in the list above."
  ${EndIf}
  MessageBox MB_OK|MB_ICONEXCLAMATION "$6" /SD IDOK
  ${If} ${Silent}
    SetErrorLevel ${EXIT_FAILED}
    Quit
  ${EndIf}
  Abort "$6"
  hubok:
SectionEnd

; the last section: Setup got this far, so it succeeded (silent mode's exit code 0)
Section "-Done"
  SetErrorLevel 0
SectionEnd

Function .onInit
  ; silent: anything that stops Setup before it is done exits 3 (the last section sets 0)
  ${If} ${Silent}
    SetErrorLevel ${EXIT_FAILED}
  ${EndIf}
  ${IfNot} ${RunningX64}
    MessageBox MB_OK|MB_ICONSTOP "Keep Hub needs 64-bit Windows." /SD IDOK
    Abort
  ${EndIf}
  ; the 64-bit registry and System32 (sc.exe, net.exe)
  SetRegView 64
  ${DisableX64FSRedirection}
  ReadEnvStr $0 "ProgramData"
  StrCpy $HubData "$0\${HUB_DATA_DIR}"
  ReadRegStr $OldVersion HKLM "${UNINSTALL_KEY}" "DisplayVersion"
  ReadRegStr $OldOrder HKLM "${UNINSTALL_KEY}" "VersionOrder"
  StrCpy $1 "Setup needs administrator approval once: Keep Hub runs as a service for the whole computer."
  ${If} $OldVersion == ""
    StrCpy $WelcomeText "Setup will install ${PRODUCT} ${VERSION} on this computer. It lets the household's phones reach the Keep and Pick apps here, over the home Wi-Fi.$\r$\n$\r$\n$1"
  ${Else}
    ; semver order: 0 the same, 1 the installed one is newer, 2 this one is newer
    StrCpy $2 2
    ${If} $OldVersion == "${VERSION}"
      StrCpy $2 0
    ${ElseIf} $OldOrder != ""
      ${VersionCompare} "$OldOrder" "${VERSION_ORDER}" $2
    ${EndIf}
    ${If} $2 == 1
      ; a hub is never replaced by an older version (acceptance test 26)
      MessageBox MB_OK|MB_ICONEXCLAMATION "${PRODUCT} $OldVersion is installed, which is newer than ${VERSION}. A hub is never replaced by an older version, so nothing was changed." /SD IDOK
      ${If} ${Silent}
        SetErrorLevel ${EXIT_NEWER_INSTALLED}
      ${EndIf}
      Abort
    ${ElseIf} $2 == 0
      StrCpy $WelcomeText "${PRODUCT} ${VERSION} is already installed; Setup will install it again. The hub's name and the paired phones are kept.$\r$\n$\r$\n$1"
    ${Else}
      StrCpy $WelcomeText "${PRODUCT} $OldVersion will be updated to ${VERSION}. The hub stops for a moment; the hub's name and the paired phones are kept.$\r$\n$\r$\n$1"
    ${EndIf}
  ${EndIf}
FunctionEnd

; ----- the uninstaller ----------------------------------------------------------------------------

Function un.onInit
  ${If} ${Silent}
    SetErrorLevel ${EXIT_FAILED}
  ${EndIf}
  SetRegView 64
  ${DisableX64FSRedirection}
  ReadEnvStr $0 "ProgramData"
  StrCpy $HubData "$0\${HUB_DATA_DIR}"
  StrCpy $DeleteData 0
  ${GetParameters} $R0

  ; the apps that still use the hub: named, and asked again (acceptance test 25)
  StrCpy $Apps ""
  ${If} ${FileExists} "$INSTDIR\${HUB_EXE}"
    nsExec::ExecToStack `"$INSTDIR\${HUB_EXE}" registered-apps --data "$HubData"`
    Pop $0
    Pop $Apps
    ; the program ends its line with a newline: drop it
    ${Do}
      StrCpy $1 $Apps 1 -1
      ${If} $1 == "$\n"
      ${OrIf} $1 == "$\r"
        StrCpy $Apps $Apps -1
      ${Else}
        ${Break}
      ${EndIf}
    ${Loop}
    ${If} $0 != 0
      StrCpy $Apps ""
    ${EndIf}
  ${EndIf}
  ${If} $Apps != ""
    ${If} ${Silent}
      ClearErrors
      ${GetOptions} $R0 "/FORCE" $R1
      ${If} ${Errors}
        ; keep-launcher asks the person itself, then runs this again with /FORCE
        SetErrorLevel ${EXIT_APPS_REGISTERED}
        Quit
      ${EndIf}
    ${Else}
      MessageBox MB_YESNO|MB_ICONEXCLAMATION|MB_DEFBUTTON2 "These apps still use Keep Hub: $Apps.$\r$\n$\r$\nTheir phones will stop connecting until Keep Hub is installed again. Remove Keep Hub anyway?" IDYES appsok
      Quit
      appsok:
    ${EndIf}
  ${EndIf}

  ; the data folder: kept unless the person also chooses to delete it
  ${If} ${Silent}
    ClearErrors
    ${GetOptions} $R0 "/DELETEDATA" $R1
    ${IfNot} ${Errors}
      StrCpy $DeleteData 1
    ${EndIf}
  ${ElseIf} ${FileExists} "$HubData\hub.json"
    MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2 "Also delete Keep Hub's data in $HubData?$\r$\n$\r$\nIt holds the hub's name, the household's members and the paired phones. Keep it, and installing Keep Hub again carries on where it left off." IDNO keepdata
    StrCpy $DeleteData 1
    keepdata:
  ${EndIf}
FunctionEnd

Section "Uninstall"
  Call un.StopHub
  DetailPrint "Removing the Keep Hub service and its firewall rule"
  nsExec::ExecToLog `"$INSTDIR\${HUB_EXE}" remove-service`
  Pop $0

  ; only the files Setup installed
  Delete "$INSTDIR\${HUB_EXE}"
  Delete "$INSTDIR\LICENSE-MIT"
  Delete "$INSTDIR\LICENSE-APACHE"
  Delete "$INSTDIR\NOTICE"
  Delete "$INSTDIR\THIRD-PARTY-LICENSES.txt"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "${UNINSTALL_KEY}"

  ${If} $DeleteData == 1
    DetailPrint "Deleting $HubData"
    RMDir /r "$HubData"
  ${ElseIf} ${FileExists} "$HubData\hub.json"
    DetailPrint "Keep Hub's data stays in $HubData"
  ${EndIf}
  SetErrorLevel 0
SectionEnd
