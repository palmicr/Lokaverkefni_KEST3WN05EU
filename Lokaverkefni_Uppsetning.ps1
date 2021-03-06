﻿function 1-time-groups {
## Basic Groups
New-ADOrganizationalUnit -Name Notendur -ProtectedFromAccidentalDeletion $false
$notOUpath = (Get-ADOrganizationalUnit -Filter { name -like 'Notendur' }).DistinguishedName
New-ADGroup -Name AllirNotendur -Path $notOUpath -GroupScope Global
##############################################
New-ADOrganizationalUnit -Name Starfsmenn -Path $notOUpath -ProtectedFromAccidentalDeletion $false
$starfOUpath = (Get-ADOrganizationalUnit -Filter { name -like 'Starfsmenn' }).DistinguishedName
New-ADGroup -Name AllirStarfsmenn -Path $starfOUpath -GroupScope Global
Add-ADGroupMember -Identity AllirNotendur -Members AllirStarfsmenn
##############################################
New-ADOrganizationalUnit -Name Nemendur -Path $notOUpath -ProtectedFromAccidentalDeletion $false
$nemOUpath = (Get-ADOrganizationalUnit -Filter { name -like 'Nemendur' }).DistinguishedName
New-ADGroup -Name AllirNemendur -Path $nemOUpath -GroupScope Global
Add-ADGroupMember -Identity AllirNotendur -Members AllirNemendur
##############################################
}

############################################################################################ USERS using CSV file ON DOMAIN CONTROLLER
function CreateUsers {
$notendur = Import-Csv .\downloads\lokaverk_notendur.csv
##############################################
$notOUpath = (Get-ADOrganizationalUnit -Filter { name -like 'Notendur' }).DistinguishedName
$starfOUpath = (Get-ADOrganizationalUnit -Filter { name -like 'Starfsmenn' }).DistinguishedName
$nemOUpath = (Get-ADOrganizationalUnit -Filter { name -like 'Nemendur' }).DistinguishedName
#Groups
    foreach ($s in $notendur){            
        $skoli = $s.Skoli      
        $hlutverk = $s.Hlutverk
        $braut = $s.Braut

        ##############################################
        ## Búa til Nemendu OU.
        if($hlutverk -eq "Nemendur"){
            $skolOUpath = (Get-ADOrganizationalUnit -SearchBase $nemOUpath -Filter { name -like $skoli }).DistinguishedName 
            $brautOUpath = (Get-ADOrganizationalUnit -SearchBase $nemOUpath -Filter { name -like $braut }).DistinguishedName
           

            if(-not(Get-ADOrganizationalUnit -SearchBase $nemOUpath -Filter { name -like $skoli })) {
                New-ADOrganizationalUnit -Name $skoli -Path $nemOUpath -ProtectedFromAccidentalDeletion $false
                $skolOUpath = (Get-ADOrganizationalUnit -SearchBase $nemOUpath -Filter { name -like $skoli }).DistinguishedName 
                New-ADGroup -Name $($skoli + "_" + $hlutverk) -Path $skolOUpath -GroupScope Global
                Add-ADGroupMember -Identity AllirNemendur -Members $($skoli + "_" + $hlutverk) 
            }
            if(-not(Get-ADOrganizationalUnit -SearchBase $skolOUpath -Filter { name -like $braut })) {
                New-ADOrganizationalUnit -Name $braut -Path $skolOUpath -ProtectedFromAccidentalDeletion $false
                $brautOUpath = (Get-ADOrganizationalUnit -SearchBase $nemOUpath -Filter { name -like $braut }).DistinguishedName
                New-ADGroup -Name $($braut + "_" + $hlutverk) -Path $brautOUpath -GroupScope Global
                Add-ADGroupMember -Identity $($skoli + "_" + $hlutverk) -Members $($braut + "_" + $hlutverk)  
            }
        }
        ##############################################
        ## Búa til Starfmanna OU.
        if(-not($hlutverk -eq "Nemendur")){
            $skolOUpath = (Get-ADOrganizationalUnit -SearchBase $starfOUpath -Filter { name -like $skoli }).DistinguishedName
            $hlutOUpath = (Get-ADOrganizationalUnit -SearchBase $starfOUpath -Filter { name -like $hlutverk }).DistinguishedName
            $brautOUpath = (Get-ADOrganizationalUnit -SearchBase $starfOUpath -Filter { name -like $braut }).DistinguishedName

            if(-not(Get-ADOrganizationalUnit -SearchBase $starfOUpath -Filter { name -like $hlutverk })) {
                New-ADOrganizationalUnit -Name $hlutverk -Path $starfOUpath -ProtectedFromAccidentalDeletion $false
                $hlutOUpath = (Get-ADOrganizationalUnit -SearchBase $starfOUpath -Filter { name -like $hlutverk }).DistinguishedName
                New-ADGroup -Name $hlutverk -Path $hlutOUpath -GroupScope Global
                Add-ADGroupMember -Identity AllirStarfsmenn -Members $hlutverk 
            }
            if(-not(Get-ADOrganizationalUnit -SearchBase $hlutOUpath -Filter { name -like $skoli })) {
                New-ADOrganizationalUnit -Name $skoli -Path $hlutOUpath -ProtectedFromAccidentalDeletion $false
                $skolOUpath = (Get-ADOrganizationalUnit -SearchBase $starfOUpath -Filter { name -like $skoli }).DistinguishedName
                New-ADGroup -Name $($skoli + "_" + $hlutverk) -Path $skolOUpath -GroupScope Global
                Add-ADGroupMember -Identity $hlutverk -Members $($skoli + "_" + $hlutverk) 
            }
            if(-not(Get-ADOrganizationalUnit -SearchBase $skolOUpath -Filter { name -like $braut })) {
                New-ADOrganizationalUnit -Name $braut -Path $skolOUpath -ProtectedFromAccidentalDeletion $false
                $brautOUpath = (Get-ADOrganizationalUnit -SearchBase $starfOUpath -Filter { name -like $braut }).DistinguishedName
                New-ADGroup -Name $($braut + "_" + $hlutverk) -Path $brautOUpath -GroupScope Global
                Add-ADGroupMember -Identity $($skoli + "_" + $hlutverk) -Members $($braut + "_" + $hlutverk)
            }
        }
        ##############################################
        #user
                if($hlutverk -eq "Nemendur"){
                    $stada = "Nemandi"
                    $n = $s.Nafn.ToLower()
                    $n = $n -replace 'á','a'
                    $n = $n -replace 'ú','u'
                    $n = $n -replace 'ð','d'
                    $n = $n -replace 'í','i'
                    $n = $n -replace 'ó','o'
                    $n = $n -replace 'ú','u'
                    $n = $n -replace 'þ','th'
                    $n = $n -replace 'æ','ae'
                    $n = $n -replace 'ö','o'
                    $n = $n -replace 'ý','y'
                    $a = $($n.Substring(0,2) + $n.Split(" ")[-1].Substring(0,2))
                    $teljari = 1
                    if(-not(Get-ADUser -Filter "SamAccountName -like '$a*'")){
                            $a = $($a + $teljari)
                    }
                    else{
                        $finnanotandi = (Get-ADUser -Filter "SamAccountName -like '$a*'")
                        foreach($fannst in $finnanotandi.SamAccountName){
                            $teljari++
                            $teljari
                        }
                        $a = $($a + $teljari)
                        $a
                        } 
                    $username = $a;
                    $username
                }
                else{
                    $stada = "Kennari"
                    $n = $s.Nafn.ToLower()
                    $n = $n -replace 'á','a'
                    $n = $n -replace 'ú','u'
                    $n = $n -replace 'ð','d'
                    $n = $n -replace 'í','i'
                    $n = $n -replace 'ó','o'
                    $n = $n -replace 'ú','u'
                    $n = $n -replace 'þ','th'
                    $n = $n -replace 'æ','ae'
                    $n = $n -replace 'ö','o'
                    $n = $n -replace 'ý','y'
                    $n = $n -replace ' ','.'
                    if($n.length -gt 20){
                        $n = $n.Substring(0,20)
                    }
                    $username = $n;
                }
                $name = $s.Nafn.Split(" ")
                if($name.length -eq 2){
                    $givenname = $name[0]
                }
                else{
                    $givenname = $name[0, -2]
                }
                $hashUser = @{
                    'Name'= $s.Nafn;
                    'Displayname'= $s.Nafn;
                    'Title' = $stada;
                    'Givenname' = "$givenname";
                    'Surname'= $s.Nafn.Split(" ")[-1];
                    'Samaccountname'= $username;
                    'UserPrincipalName' = $($username + "@" + $env:USERDNSDOMAIN);
                    'Path'= $brautOUpath;
                    'AccountPassword'= (ConvertTo-SecureString -AsPlainText "pass.123" -Force);
                    'Enabled' = $true;
                 }
                 New-ADUser @hashUser
                 Add-ADGroupMember -Identity $($braut + "_" + $hlutverk) -Members $username
    }
}



############################################################################################ Do NO USE ON DOMAIN CONTROLLER
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
        New-Website -Name "$userN.tskloi.is" -HostHeader "$userN.tskloi.is" -PhysicalPath "C:\inetpub\wwwroot\$userN.tskloi.is"
        New-WebBinding -Name $($userN +".tskloi.is") -HostHeader $("www." + $userN +".eep.is")
 
        #sæki núverandi réttindi
        $rettindi = Get-Acl -Path C:\inetpub\wwwroot\$userN.tskloi.is
        #bý til þau réttindi sem ég ætla að bæta við möppuna
        $nyrettindi = New-Object System.Security.AccessControl.FileSystemAccessRule($($env:userdomain + "\" + $userN),"Modify","Allow")
        $nyrettindi2 = New-Object System.Security.AccessControl.FileSystemAccessRule($($env:userdomain + "\tölvubraut_kennarar"),"Modify","Allow")
        #Hver á að fá réttindin, hvaða réttindi á viðkomandi að fá, erum við að leyfa eða banna (allow eða deny)
        #bæti nýju réttindunum við þau sem ég sótti áðan
        $rettindi.AddAccessRule($nyrettindi)
        $rettindi.AddAccessRule($nyrettindi2)
        #Set réttindin aftur á möppuna
        Set-Acl -Path "C:\inetpub\wwwroot\$userN.tskloi.is" $rettindi                  
        }

        ############################################## 1 Time use
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
        ##############################################

        ############################################## Eftir að allir noteindur eru gerðir, nota þetta til að ger síður fyrir alla 
        $OU = "OU=Tölvubraut,OU=Upplýsingatækniskólinn,OU=Nemendur,OU=Notendur,DC=tskloi19,DC=Local"
        $vefnotendur = ($OU | ForEach{Get-AdUser -filter * -SearchBase $_}).SamAccountName

        ForEach($v in $vefnotendur){
            buildSite -userN $v
        }


############################################################################################ Do NO USE ON DOMAIN CONTROLLER
#import SQL Server module
Import-Module SQLPS -DisableNameChecking

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
