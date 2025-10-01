# AutoIT Development Guide for Claude Code

## When to Use This Guide
- Desktop automation scripts on Windows
- GUI automation and testing
- Windows system administration tasks
- Legacy application integration
- Unattended installations and configurations

## AutoIT-Specific Best Practices

### Script Structure and Organization
```autoit
#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Icon=myicon.ico
#AutoIt3Wrapper_Outfile=MyScript.exe
#AutoIt3Wrapper_Compression=4
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

#include <ButtonConstants.au3>
#include <EditConstants.au3>
#include <GUIConstantsEx.au3>
#include <WindowsConstants.au3>
#include <File.au3>
#include <Array.au3>

; Global variables
Global $g_hMainGUI
Global $g_sLogFile = @ScriptDir & "\automation.log"

; Main execution
Main()

Func Main()
    WriteLog("Script started")

    ; Your main logic here

    WriteLog("Script completed")
EndFunc
```

### Error Handling and Logging
```autoit
Func WriteLog($sMessage)
    Local $sTimestamp = @YEAR & "-" & @MON & "-" & @MDAY & " " & @HOUR & ":" & @MIN & ":" & @SEC
    FileWriteLine($g_sLogFile, $sTimestamp & " - " & $sMessage)
EndFunc

Func HandleError($sFunction, $sError)
    WriteLog("ERROR in " & $sFunction & ": " & $sError)
    MsgBox($MB_ICONERROR, "Error", "An error occurred in " & $sFunction & @CRLF & $sError)
EndFunc

; Example with error handling
Func SafeWinActivate($sTitle, $iTimeout = 5000)
    Local $hTimer = TimerInit()

    While TimerDiff($hTimer) < $iTimeout
        If WinExists($sTitle) Then
            WinActivate($sTitle)
            If WinActive($sTitle) Then
                WriteLog("Successfully activated window: " & $sTitle)
                Return True
            EndIf
        EndIf
        Sleep(100)
    WEnd

    HandleError("SafeWinActivate", "Could not activate window: " & $sTitle)
    Return False
EndFunc
```

### Window and Control Management
```autoit
; Robust window handling
Func WaitForWindow($sTitle, $iTimeout = 10000)
    Local $hTimer = TimerInit()

    While TimerDiff($hTimer) < $iTimeout
        If WinExists($sTitle) Then
            WriteLog("Window found: " & $sTitle)
            Return True
        EndIf
        Sleep(250)
    WEnd

    Return False
EndFunc

; Safe control interaction
Func SafeControlClick($sTitle, $sControl, $iRetries = 3)
    For $i = 1 To $iRetries
        If WinExists($sTitle) Then
            WinActivate($sTitle)
            Sleep(500)

            If ControlClick($sTitle, "", $sControl) Then
                WriteLog("Successfully clicked control: " & $sControl)
                Return True
            EndIf
        EndIf

        WriteLog("Retry " & $i & " for control click: " & $sControl)
        Sleep(1000)
    Next

    HandleError("SafeControlClick", "Failed to click control: " & $sControl)
    Return False
EndFunc
```

### GUI Development
```autoit
Func CreateMainGUI()
    $g_hMainGUI = GUICreate("Automation Tool", 400, 300, -1, -1)

    ; Controls
    Local $btnStart = GUICtrlCreateButton("Start Automation", 50, 50, 120, 30)
    Local $btnStop = GUICtrlCreateButton("Stop", 200, 50, 120, 30)
    Local $lblStatus = GUICtrlCreateLabel("Ready", 50, 100, 300, 20)
    Local $txtLog = GUICtrlCreateEdit("", 50, 130, 300, 120, $ES_READONLY + $WS_VSCROLL)

    GUISetState(@SW_SHOW, $g_hMainGUI)

    While 1
        Local $nMsg = GUIGetMsg()
        Switch $nMsg
            Case $GUI_EVENT_CLOSE
                ExitLoop
            Case $btnStart
                StartAutomation()
            Case $btnStop
                StopAutomation()
        EndSwitch
    WEnd

    GUIDelete($g_hMainGUI)
EndFunc
```

### File and Registry Operations
```autoit
; Safe file operations
Func SafeFileRead($sFilePath)
    If Not FileExists($sFilePath) Then
        HandleError("SafeFileRead", "File does not exist: " & $sFilePath)
        Return ""
    EndIf

    Local $hFile = FileOpen($sFilePath, $FO_READ)
    If $hFile = -1 Then
        HandleError("SafeFileRead", "Cannot open file: " & $sFilePath)
        Return ""
    EndIf

    Local $sContent = FileRead($hFile)
    FileClose($hFile)

    WriteLog("Successfully read file: " & $sFilePath)
    Return $sContent
EndFunc

; Registry operations with error handling
Func SafeRegRead($sKeyName, $sValueName)
    Local $result = RegRead($sKeyName, $sValueName)
    If @error Then
        HandleError("SafeRegRead", "Cannot read registry: " & $sKeyName & "\" & $sValueName)
        Return ""
    EndIf

    WriteLog("Successfully read registry: " & $sKeyName & "\" & $sValueName)
    Return $result
EndFunc
```

### Security Considerations
```autoit
; Input validation
Func ValidateInput($sInput, $sType = "string")
    Switch $sType
        Case "number"
            If Not IsNumber($sInput) Then
                HandleError("ValidateInput", "Invalid number: " & $sInput)
                Return False
            EndIf
        Case "path"
            ; Remove potentially dangerous characters
            $sInput = StringRegExpReplace($sInput, '[<>:"|?*]', "")
            If StringLen($sInput) = 0 Then
                HandleError("ValidateInput", "Invalid path after sanitization")
                Return False
            EndIf
        Case "filename"
            ; Validate filename
            If StringRegExp($sInput, '[\\/:*?"<>|]') Then
                HandleError("ValidateInput", "Invalid filename: " & $sInput)
                Return False
            EndIf
    EndSwitch

    Return True
EndFunc

; Secure credential handling
Func GetSecureCredentials()
    ; Never hardcode credentials
    Local $sUsername = InputBox("Credentials", "Username:", "", "", 200, 130)
    If @error Then Return False

    Local $sPassword = InputBox("Credentials", "Password:", "", "*", 200, 130)
    If @error Then Return False

    ; Use credentials immediately, don't store in variables longer than necessary
    Local $bResult = AuthenticateUser($sUsername, $sPassword)

    ; Clear sensitive data
    $sUsername = ""
    $sPassword = ""

    Return $bResult
EndFunc
```

### Process and Service Management
```autoit
; Safe process handling
Func SafeProcessClose($sProcessName, $iTimeout = 5000)
    If Not ProcessExists($sProcessName) Then
        WriteLog("Process not running: " & $sProcessName)
        Return True
    EndIf

    WriteLog("Attempting to close process: " & $sProcessName)
    ProcessClose($sProcessName)

    Local $hTimer = TimerInit()
    While TimerDiff($hTimer) < $iTimeout
        If Not ProcessExists($sProcessName) Then
            WriteLog("Process successfully closed: " & $sProcessName)
            Return True
        EndIf
        Sleep(100)
    WEnd

    WriteLog("Force terminating process: " & $sProcessName)
    Run("taskkill /F /IM " & $sProcessName, "", @SW_HIDE)
    Sleep(1000)

    Return Not ProcessExists($sProcessName)
EndFunc

; Service management
Func ManageService($sServiceName, $sAction)
    Local $iPID = Run("sc " & $sAction & " " & $sServiceName, "", @SW_HIDE, $STDERR_CHILD + $STDOUT_CHILD)
    ProcessWaitClose($iPID)

    Local $sOutput = StdoutRead($iPID)
    Local $sError = StderrRead($iPID)

    If $sError Then
        HandleError("ManageService", "Service operation failed: " & $sError)
        Return False
    EndIf

    WriteLog("Service operation successful: " & $sAction & " " & $sServiceName)
    Return True
EndFunc
```

### Testing and Debugging
```autoit
; Debug mode flag
Global $g_bDebugMode = True

Func DebugLog($sMessage)
    If $g_bDebugMode Then
        ConsoleWrite(@HOUR & ":" & @MIN & ":" & @SEC & " DEBUG: " & $sMessage & @CRLF)
        WriteLog("DEBUG: " & $sMessage)
    EndIf
EndFunc

; Screenshot for debugging
Func TakeDebugScreenshot($sDescription = "")
    If $g_bDebugMode Then
        Local $sFilename = @ScriptDir & "\debug_" & @YEAR & @MON & @MDAY & "_" & @HOUR & @MIN & @SEC & ".png"
        _ScreenCapture_Capture($sFilename)
        DebugLog("Screenshot taken: " & $sFilename & " - " & $sDescription)
    EndIf
EndFunc

; Test function wrapper
Func RunTest($sFunctionName, $aParams = 0)
    DebugLog("Starting test: " & $sFunctionName)
    Local $hTimer = TimerInit()

    Local $result
    If IsArray($aParams) Then
        $result = Call($sFunctionName, $aParams[0], $aParams[1], $aParams[2], $aParams[3], $aParams[4])
    Else
        $result = Call($sFunctionName)
    EndIf

    Local $iElapsed = TimerDiff($hTimer)
    DebugLog("Test completed: " & $sFunctionName & " - Time: " & $iElapsed & "ms - Result: " & $result)

    Return $result
EndFunc
```

### Performance Optimization
```autoit
; Efficient array operations
Func ProcessLargeArray(ByRef $aData)
    Local $iUBound = UBound($aData)

    ; Pre-allocate result array
    Local $aResult[$iUBound]

    ; Process in batches to avoid memory issues
    Local $iBatchSize = 1000
    For $i = 0 To $iUBound - 1 Step $iBatchSize
        Local $iEnd = ($i + $iBatchSize > $iUBound) ? $iUBound - 1 : $i + $iBatchSize - 1

        For $j = $i To $iEnd
            $aResult[$j] = ProcessItem($aData[$j])
        Next

        ; Allow other processes to run
        Sleep(1)
    Next

    Return $aResult
EndFunc

; Memory management
Func CleanupMemory()
    ; Clear large arrays
    Global $g_aLargeArray[1] = [""]

    ; Force garbage collection
    _ArraySort($g_aLargeArray)

    WriteLog("Memory cleanup completed")
EndFunc
```

### Common Automation Patterns
```autoit
; Web browser automation
Func AutomateBrowser($sURL, $sAction)
    ; Use WebDriver instead of IE object for modern browsers
    Local $sDriver = @ScriptDir & "\chromedriver.exe"

    If Not FileExists($sDriver) Then
        HandleError("AutomateBrowser", "ChromeDriver not found: " & $sDriver)
        Return False
    EndIf

    ; Launch browser with WebDriver
    Local $iPID = Run($sDriver & " --port=9515", "", @SW_HIDE)
    Sleep(2000)

    ; Use HTTP requests to control browser
    ; Implementation depends on WebDriver API

    ProcessClose($iPID)
    Return True
EndFunc

; Excel automation
Func AutomateExcel($sFilePath, $sOperation)
    Local $oExcel = ObjCreate("Excel.Application")
    If @error Then
        HandleError("AutomateExcel", "Cannot create Excel application object")
        Return False
    EndIf

    $oExcel.Visible = False
    $oExcel.DisplayAlerts = False

    Local $oWorkbook = $oExcel.Workbooks.Open($sFilePath)
    If @error Then
        $oExcel.Quit()
        HandleError("AutomateExcel", "Cannot open Excel file: " & $sFilePath)
        Return False
    EndIf

    ; Perform operations
    Switch $sOperation
        Case "export_csv"
            $oWorkbook.SaveAs(@ScriptDir & "\export.csv", 6) ; CSV format
        Case "update_data"
            Local $oWorksheet = $oWorkbook.Worksheets(1)
            $oWorksheet.Cells(1, 1).Value = "Updated: " & @YEAR & "-" & @MON & "-" & @MDAY
    EndSwitch

    $oWorkbook.Save()
    $oWorkbook.Close()
    $oExcel.Quit()

    WriteLog("Excel automation completed: " & $sOperation)
    Return True
EndFunc
```

## Development Workflow

### 1. Setup and Planning
```autoit
; Standard script header
#pragma compile(Icon, icon.ico)
#pragma compile(FileDescription, Script Description)
#pragma compile(ProductVersion, 1.0.0.0)
#pragma compile(FileVersion, 1.0.0.0)
#pragma compile(LegalCopyright, Your Company)

; Include required libraries
#include <Constants.au3>
#include <File.au3>
#include <Array.au3>
```

### 2. Configuration Management
```autoit
; INI file configuration
Func LoadConfig()
    Local $sConfigFile = @ScriptDir & "\config.ini"

    If Not FileExists($sConfigFile) Then
        CreateDefaultConfig($sConfigFile)
    EndIf

    Global $g_sTargetApp = IniRead($sConfigFile, "Settings", "TargetApp", "")
    Global $g_iTimeout = Number(IniRead($sConfigFile, "Settings", "Timeout", "10000"))
    Global $g_bDebugMode = (IniRead($sConfigFile, "Settings", "DebugMode", "false") = "true")
EndFunc

Func CreateDefaultConfig($sFilePath)
    IniWrite($sFilePath, "Settings", "TargetApp", "notepad.exe")
    IniWrite($sFilePath, "Settings", "Timeout", "10000")
    IniWrite($sFilePath, "Settings", "DebugMode", "false")
    WriteLog("Created default configuration: " & $sFilePath)
EndFunc
```

### 3. Testing Strategy
```autoit
; Unit testing framework
Func RunAllTests()
    Local $aTests[] = ["TestWindowHandling", "TestFileOperations", "TestRegistryAccess"]
    Local $iPassCount = 0
    Local $iFailCount = 0

    For $i = 0 To UBound($aTests) - 1
        If Call($aTests[$i]) Then
            $iPassCount += 1
            WriteLog("PASS: " & $aTests[$i])
        Else
            $iFailCount += 1
            WriteLog("FAIL: " & $aTests[$i])
        EndIf
    Next

    WriteLog("Test Results: " & $iPassCount & " passed, " & $iFailCount & " failed")
    Return ($iFailCount = 0)
EndFunc

Func TestWindowHandling()
    ; Test window activation
    Run("notepad.exe")
    Sleep(1000)

    If Not WaitForWindow("Untitled - Notepad", 5000) Then Return False
    If Not SafeWinActivate("Untitled - Notepad") Then Return False

    WinClose("Untitled - Notepad")
    Return True
EndFunc
```

### 4. Deployment and Distribution
```autoit
; Compile with proper settings
#AutoIt3Wrapper_Res_Fileversion=1.0.0.0
#AutoIt3Wrapper_Res_ProductVersion=1.0.0.0
#AutoIt3Wrapper_Res_CompanyName=Your Company
#AutoIt3Wrapper_Res_Description=Automation Script
#AutoIt3Wrapper_Res_Fileversion_AutoIncrement=y

; Installation routine
Func InstallScript()
    Local $sInstallDir = @ProgramFilesDir & "\YourAutomationTool"

    If Not DirCreate($sInstallDir) Then
        HandleError("InstallScript", "Cannot create installation directory")
        Return False
    EndIf

    ; Copy files
    FileCopy(@ScriptFullPath, $sInstallDir & "\automation.exe")
    FileCopy(@ScriptDir & "\config.ini", $sInstallDir & "\config.ini")

    ; Create shortcuts
    FileCreateShortcut($sInstallDir & "\automation.exe", @DesktopDir & "\Automation Tool.lnk")

    WriteLog("Installation completed successfully")
    Return True
EndFunc
```

## Integration with External Systems

### Command Line Integration
```autoit
; Parse command line arguments
Func ParseCommandLine()
    Local $aCmdLine = $CmdLine

    For $i = 1 To $aCmdLine[0]
        Local $aArg = StringSplit($aCmdLine[$i], "=")
        If $aArg[0] = 2 Then
            Switch $aArg[1]
                Case "/debug"
                    $g_bDebugMode = True
                Case "/config"
                    LoadCustomConfig($aArg[2])
                Case "/target"
                    $g_sTargetApp = $aArg[2]
            EndSwitch
        EndIf
    Next
EndFunc
```

### PowerShell Integration
```autoit
Func RunPowerShellScript($sScript)
    Local $sTempFile = @TempDir & "\autoit_ps_" & @MSEC & ".ps1"

    FileWrite($sTempFile, $sScript)

    Local $iPID = Run("powershell.exe -ExecutionPolicy Bypass -File " & $sTempFile, "", @SW_HIDE, $STDERR_CHILD + $STDOUT_CHILD)
    ProcessWaitClose($iPID)

    Local $sOutput = StdoutRead($iPID)
    Local $sError = StderrRead($iPID)

    FileDelete($sTempFile)

    If $sError Then
        HandleError("RunPowerShellScript", $sError)
        Return ""
    EndIf

    Return $sOutput
EndFunc
```

## Common Pitfalls and Solutions

### 1. Timing Issues
- Always use proper waits instead of fixed Sleep() calls
- Implement timeout mechanisms for all operations
- Use WinWait() and ControlWait() functions

### 2. Window Handling
- Always check if windows exist before interacting
- Use proper window titles or handles
- Account for DPI scaling on high-resolution displays

### 3. Error Recovery
- Implement retry mechanisms for flaky operations
- Always clean up resources (close files, quit applications)
- Provide meaningful error messages and logging

### 4. Performance
- Avoid excessive Sleep() calls
- Use efficient array operations
- Implement proper memory management for large datasets

This guide ensures robust, maintainable AutoIT scripts that integrate well with larger automation workflows while following security and performance best practices.

*This document covers AutoIt scripting best practices and should be used alongside universal patterns. For consolidated security guidance including environment variables and secrets management, see security-guidelines.md.*