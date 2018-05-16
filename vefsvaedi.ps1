  function buildSite{
        param(
            [Parameter(Mandatory=$true, HelpMessage="Sláðu inn Notendanafn")]
            [string]$userN  
        )
        # Búa til nýja möppu í wwwroot
        New-Item "C:\inetpub\wwwroot\$userN.tskloi.is" -ItemType Directory
        # Búa til html skjal sem inniheldur "Vefsíðan www.eep.is" í nýju möppuna
        New-Item "C:\inetpub\wwwroot\$userN.tskloi.is\index.html" -ItemType File -Value "Vefsíðan $userN.tskloi.is"
        # Búa til nýja vefsíðu á vefþjóninn
        #New-Website -Name "$userN.tskloi.is" -HostHeader "$userN.tskloi.is" -PhysicalPath "C:\inetpub\wwwroot\$userN.tskloi.is"
        #New-WebBinding -Name $($userN +".tskloi.is") -HostHeader $("www." + $userN +".eep.is")
 
        #sæki núverandi réttindi
        $rettindi = Get-Acl -Path C:\inetpub\wwwroot\$userN.tskloi.is
        #bý til þau réttindi sem ég ætla að bæta við möppuna
        $nyrettindi = New-Object System.Security.AccessControl.FileSystemAccessRule($($env:userdomain + "\" + $userN),"Modify","Allow")
        $nyrettindi2 = New-Object System.Security.AccessControl.FileSystemAccessRule($($env:userdomain + "\tölvubraut_kennarar"),"Modify","Allow")
        $nyrettindi3 = New-Object System.Security.AccessControl.FileSystemAccessRule($("WIN3A-10\IIS_IUSRS"),"Modify","Allow")
        #Hver á að fá réttindin, hvaða réttindi á viðkomandi að fá, erum við að leyfa eða banna (allow eða deny)
        #bæti nýju réttindunum við þau sem ég sótti áðan
        $rettindi.AddAccessRule($nyrettindi)
        $rettindi.AddAccessRule($nyrettindi2)
        $rettindi.AddAccessRule($nyrettindi3)
        $rettindi.SetAccessRuleProtection($true,$true)
        #Set réttindin aftur á möppuna
        Set-Acl -Path "C:\inetpub\wwwroot\$userN.tskloi.is" $rettindi                  
    }
Invoke-Command -ComputerName Win3a-09 -ScriptBlock {Add-DnsServerPrimaryZone -Name "tskloi.is" -ReplicationScope Domain}
Invoke-Command -ComputerName Win3a-09 -ScriptBlock {Add-DnsServerResourceRecordA -ZoneName "tskloi.is" -Name "*" -IPv4Address "172.16.0.2"}
# Setja inn IIS role-ið, þarf bara að gera einu sinni.
Install-WindowsFeature web-server -IncludeManagementTools
# Búa til nýja möppu í wwwroot
New-Item "C:\inetpub\wwwroot\www.tskloi.is" -ItemType Directory
 
# Búa til html skjal sem inniheldur "Vefsíðan www.skoli.is" í nýju möppuna
New-Item "C:\inetpub\wwwroot\www.tskloi.is\index.html" -ItemType File -Value "Vefsíðan www.tskloi.is"
 
# Búa til nýja vefsíðu á vefþjóninn
New-Website -Name "www.tskloi.is" -HostHeader "www.tskloi.is" -PhysicalPath "C:\inetpub\wwwroot\www.tskloi.is"
# Ef það þarf að bæta við fleiri hostheader-um má gera það

$OU = "OU=Tölvubraut,OU=Upplýsingatækniskólinn,OU=Nemendur,OU=Notendur,DC=tskloi19,DC=Local"
$vefnotendur = ($OU | ForEach{Get-AdUser -filter * -SearchBase $_}).SamAccountName
ForEach($v in $vefnotendur){
    buildSite -userN $v
}
