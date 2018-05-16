function CreateUser {
        param(
            [Parameter(Mandatory=$true, HelpMessage="Sláðu inn fullt nafn")]
            [string]$nafn, 
            [Parameter(Mandatory=$true, HelpMessage="Sláðu inn skólann")]
            [string]$skoli, 
            [Parameter(Mandatory=$true, HelpMessage="Sláðu inn sláðu inn hlutverk (kennari/nemandi)")]
            [string]$hlutverk,
            [Parameter(Mandatory=$true, HelpMessage="Sláðu braut")]
            [string]$braut
        )
##############################################
$notOUpath = (Get-ADOrganizationalUnit -Filter { name -like 'Notendur' }).DistinguishedName
$starfOUpath = (Get-ADOrganizationalUnit -Filter { name -like 'Starfsmenn' }).DistinguishedName
$nemOUpath = (Get-ADOrganizationalUnit -Filter { name -like 'Nemendur' }).DistinguishedName
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
elseif($hlutverk -eq "Kennarar"){
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
        $starfOUpath
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
else{
    if(-not(Get-ADOrganizationalUnit -SearchBase $starfOUpath -Filter { name -like $hlutverk })) {
        New-ADOrganizationalUnit -Name $hlutverk -Path $starfOUpath -ProtectedFromAccidentalDeletion $false
        $hlutOUpath = (Get-ADOrganizationalUnit -SearchBase $starfOUpath -Filter { name -like $hlutverk }).DistinguishedName
        New-ADGroup -Name $hlutverk -Path $hlutOUpath -GroupScope Global
        Add-ADGroupMember -Identity AllirStarfsmenn -Members $hlutverk 
    }
}
##############################################
#user
        if($hlutverk -eq "Nemendur"){
            $stada = "Nemandi"
            $n = $nafn.ToLower()
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
                }
                $a = $($a + $teljari)
                } 
            $username = $a;
            $pathing = $brautOUpath;
        }
        elseif($hlutverk -eq "Kennarar"){
            $stada = "Kennari"
            $n = $nafn.ToLower()
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
            $n = $n -replace '\.', ''
            $n = $n -replace ' ','.'
            if($n.length -gt 20){
                $n = $n.Substring(0,20)
            }
            $username = $n;
            $pathing = $brautOUpath;
        }
        else{
            Write-Output "we made it"
            $stada = "Starfsmaður"
            $n = $nafn.ToLower()
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
            $n = $n -replace '\.', ''
            $n = $n -replace ' ','.'
            if($n.length -gt 20){
                $n = $n.Substring(0,20)
            }
            $username = $n;
            $pathing = $hlutOUpath;
        }
        $name = $nafn.Split(" ")
        if($name.length -eq 2){
            $givenname = $name[0]
        }
        else{
            $givenname = $name[0, -2]
        }
        $hashUser = @{
            'Name'= $nafn;
            'Displayname'= $nafn;
            'Title' = $stada;
            'Givenname' = "$givenname";
            'Surname'= $nafn.Split(" ")[-1];
            'Samaccountname'= $username;
            'UserPrincipalName' = $($username + "@" + $env:USERDNSDOMAIN);
            'Path'= $pathing;
            'AccountPassword'= (ConvertTo-SecureString -AsPlainText "pass.123" -Force);
            'Enabled' = $true;
            }
            New-ADUser @hashUser
            if($hlutverk -eq "Kennarar" -or $hlutverk -eq "Nemendur"){
                Add-ADGroupMember -Identity $($braut + "_" + $hlutverk) -Members $username
            }
            else{
                Add-ADGroupMember -Identity $hlutverk -Members $username
            }
        if($hlutverk -eq "Nemendur" -and $skoli -eq "Upplýsingatækniskólinn" -and $braut -eq "Tölvubraut"){
            Invoke-Command -ComputerName Win3a-10 -ArgumentList $username -ScriptBlock {
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
                    $rettindi.AddAccessRule($true, $true)
                    #Set réttindin aftur á möppuna
                    Set-Acl -Path "C:\inetpub\wwwroot\$userN.tskloi.is" $rettindi                  
                }
                buildSite -userN $args[0]
            } 
        }
        Invoke-Command -ComputerName Win3a-10 -ArgumentList $username -ScriptBlock {
        function buildSql{
        param(
            [Parameter(Mandatory=$true, HelpMessage="Sláðu inn Notendarnafnið")]
            [string]$username
        )
                Import-Module SQLPS -DisableNameChecking
                $TBkennarar = (Get-ADGroup -Identity "Tölvubraut_Kennarar").Name
                Invoke-Sqlcmd -Query $("CREATE DATABASE " + $username + ";")  -ServerInstance "WIN3A-10"
                Invoke-Sqlcmd -Query $("USE " + $username + "; CREATE LOGIN [tskloi19\" +  $username + "] FROM WINDOWS WITH DEFAULT_DATABASE = [" + $username + "];") -ServerInstance "WIN3A-10"
                Invoke-Sqlcmd -Query $("ALTER AUTHORIZATION ON DATABASE::" + $username + " TO " + $username +";") -ServerInstance "WIN3A-10"  
                Invoke-Sqlcmd -Query $("USE " + $username + ";ALTER ROLE db_owner ADD MEMBER " + "[tskloi19\" + $TBkennarar +";") -ServerInstance "WIN3A-10"  
            }
            buildSql -username $args[0]
        }
}
CreateUser -nafn "Testin34 testari9 testsonin8" -skoli "Upplýsingatækniskólinn" -hlutverk "Nemendur" -braut "Tölvubraut"