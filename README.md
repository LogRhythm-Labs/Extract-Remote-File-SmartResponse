
        LogRhythm Security Operations
        Remote File Extraction SmartResponse
		Greg Foss | @heinzarelli | greg.foss@logrhythm.com
		v0.1 -- December, 2016

## [About]

Recently, a question was posted on the LogRhythm Community Portal around how to extract the LogRhythm SCSM file from a remote Windows server. Fortunately, this is easily accomplished using PowerShell remoting, however we can do much more than extract remote log files. This script allows you to copy any remote file to the local system quickly and easily.

![Extract=Files](/images/extract-file.png)

## [How To]

#####Extract Remote LogRhythm System Monitor Log Files:

		PS C:\> .\extract-file.ps1 -target 10.10.10.10 -file <LogRhythm log file name>
			or
		PS C:\> .\extract-file.ps1 -target 10.10.10.10 -file <LR File name> -username <name> -password <pass>

        LogRhythm File Name can be any of the following:
            scsm
            filemon
            regmon
            rtfim

    Caveats:
        You will need to ensure that psremoting and remote signed execution is enabled on the remote host.

#####Extract Other Remote Files:

        Extract a file and store it in the folder the script resides in:
            PS C:\> .\extract-file.ps1 -target 10.10.10.10 -file "Full File Path"

        Extract a file and store it in a separate location on the local system:
            PS C:\> .\extract-file.ps1 -target 10.10.10.10 -file "Full File Path" -location "C:\"

#####What if PSRemoting and Unrestricted Execution are disabled?

    Remotely enable PSRemoting and Unrestricted PowerShell Execution using PsExec and PSSession, then run PSRecon

        Option 1 -- WMI:
            PS C:\> wmic /node:"10.10.10.10" process call create "powershell -noprofile -command Enable-PsRemoting -Force" -Credential Get-Credential

        Option 2 - PsExec:
            PS C:\> PsExec.exe \\10.10.10.10 -u [admin account name] -p [admin account password] -h -d powershell.exe "Enable-PSRemoting -Force"

        Next...

            PS C:\> Test-WSMan 10.10.10.10
            PS C:\> Enter-PSSession 10.10.10.10
            [10.10.10.10]: PS C:\> Set-ExecutionPolicy RemoteSigned -Force

        Then run the extract-file.ps1 script as described above. Be careful to lock down who has the ability to execute PowerShell on the host remotely.

## [Parameter Breakdown]

		-target 	:	Define the remote host to restart the SCSM agent on.
        -file       :   The remote file or logrhythm log that you would like to extract
        -location   :   The local directory where the file will be copied to.
                        If not supplied, this defaults to the directory the script was executed from.
		-username 	:	Administrative Username - can be supplied on the command-line or hard-coded into the script.
		-password 	: 	Administrative Password - can be supplied on the command-line or hard-coded into the script. <== Bad idea!!

        If neither username / password parameter is supplied, you will be prompted for credentials -- the safest option aside from local execution.

## [License]

Copyright (c) 2016 LogRhythm

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.