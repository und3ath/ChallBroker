$brokerDir =  "C:\ProgramData\ChallBroker"

if(Test-Path -Path $brokerDir -eq $false) {
    New-Item -ItemType Directory -Path $brokerDir -Force
}


sc.exe create ChallBroker binpath=ChallBroker.exe start=auto