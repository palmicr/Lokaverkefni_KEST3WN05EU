functon 1-time-groups {
## Basic Groups
New-ADOrganizationalUnit -Name Notendur -ProtectedFromAccidentalDeletion $false
$notOUpath = (Get-ADOrganizationalUnit -Filter { name -like 'Notendur' }).DistinguishedName
New-ADGroup -Name AllirNotendur -Path $notOUpath -GroupScope Global
##############################################
New-ADOrganizationalUnit -Name Starfsmenn -Path $notOUpath -ProtectedFromAccidentalDeletion $false
$starfOUpath = (Get-ADOrganizationalUnit -Filter { name -like 'Starfsmenn' }).DistinguishedName
New-ADGroup -Name AllirStarfsmenn -Path $starfOUpath -GroupScope Global
##############################################
New-ADOrganizationalUnit -Name Nemendur -Path $notOUpath -ProtectedFromAccidentalDeletion $false
$nemOUpath = (Get-ADOrganizationalUnit -Filter { name -like 'Nemendur' }).DistinguishedName
New-ADGroup -Name AllirNemendur -Path $nemOUpath -GroupScope Global
##############################################
}

functon CreateUsers {
$notendur = Import-Csv .\lokaverk_notendur.csv
##############################################
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

            if(-not(Get-ADOrganizationalUnit -Path $nemOUpath -Filter { name -like $skoli })) {
            New-ADOrganizationalUnit -Name $skoli -Path $nemOUpath -ProtectedFromAccidentalDeletion $false
            New-ADGroup -Name $skoli -Path $("ou=" + $skoli + "," + $skolOUpath) -GroupScope Global
            Add-ADGroupMember -Identity AllirNemendur -Members $skoli 
            }
            if(-not(Get-ADOrganizationalUnit -Path $skolOUpath -Filter { name -like $braut })) {
            New-ADOrganizationalUnit -Name $braut -Path $skolOUpath -ProtectedFromAccidentalDeletion $false
            New-ADGroup -Name $braut -Path $("ou=" + $skoli + "," + $brautOUpath) -GroupScope Global
            Add-ADGroupMember -Identity $skoli -Members $braut  
            }
        }
        ##############################################
        ## Búa til Starfmanna OU.
        if(-not($hlutverk -eq "Nemendur")){
            $skolOUpath = (Get-ADOrganizationalUnit -SearchBase $starfOUpath -Filter { name -like $skoli }).DistinguishedName
            $hlutOUpath = (Get-ADOrganizationalUnit -SearchBase $starfOUpath -Filter { name -like $hlutverk }).DistinguishedName
            $brautOUpath = (Get-ADOrganizationalUnit -SearchBase $starfOUpath -Filter { name -like $braut }).DistinguishedName

            if(-not(Get-ADOrganizationalUnit -Path $starfOUpath -Filter { name -like $hlutverk })) {
            New-ADOrganizationalUnit -Name $hlutverk -Path $starfOUpath -ProtectedFromAccidentalDeletion $false
            New-ADGroup -Name $hlutverk -Path $("ou=" + $hlutverk + "," + $hlutOUpath) -GroupScope Global
            Add-ADGroupMember -Identity AllirStarsmenn -Members $hlutverk 
            }
            if(-not(Get-ADOrganizationalUnit -Path $hlutOUpath -Filter { name -like $skoli })) {
            New-ADOrganizationalUnit -Name $skoli -Path $hlutOUpath -ProtectedFromAccidentalDeletion $false
            New-ADGroup -Name $skoli -Path $("ou=" + $skoli + "," + $skolOUpath) -GroupScope Global
            Add-ADGroupMember -Identity $hlutverk -Members $skoli 
            }
            if(-not(Get-ADOrganizationalUnit -Path $skolOUpath -Filter { name -like $braut })) {
            New-ADOrganizationalUnit -Name $braut -Path $skolOUpath -ProtectedFromAccidentalDeletion $false
            New-ADGroup -Name $braut -Path $("ou=" + $skoli + "," + $brautOUpath) -GroupScope Global
            Add-ADGroupMember -Identity $skoli -Members $braut
            }
        }
        ##############################################
        #user
                 $hashUser = @{
                 Name = $n.nafn 
                 Title = $n.starfsheiti
                 State = $n.sveitarfelag
                 DisplayName = $n.nafn 
                 GivenName = $n.fornafn 
                 Surname = $n.eftirnafn
                 HomePhone = $n.heimasimi
                 OfficePhone =  $n.vinnusimi
                 MobilePhone = $n.farsimi
                 Department = $n.deild 
                 SamAccountName = $n.notendanafn 
                 UserPrincipalName = $($n.notendanafn + "@" + $env:USERDNSDOMAIN) 
                 Path = $("ou=" + $deild + "," + $grunnOUpath) 
                 AccountPassword = (ConvertTo-SecureString -AsPlainText "pass.123" -Force) 
                 Enabled = $true
                }

        New-ADUser @hashUser
        ##############################################
        #Create Web and Sql
        if($hlutverk -eq "Nemandi"){

        }
        ##############################################
        #Create Sql

    }
}



##############################################
    function buildSite{
        param(
            [Parameter(Mandatory=$true, HelpMessage="Sláðu inn Username")]
            [string]$userN  
        )

        Add-DnsServerResourceRecord -CName -Name "$userN" -HostNameAlias "www.tskloi.is" -ZoneName "tskloi.is"

        # Búa til nýja möppu í wwwroot
        New-Item "C:\inetpub\wwwroot\$userN.tskloi.is" -ItemType Directory
        # Búa til html skjal sem inniheldur "Vefsíðan www.eep.is" í nýju möppuna
        New-Item "C:\inetpub\wwwroot\$userN.tskloi.is\index.html" -ItemType File -Value "Vefsíðan $userN.tskloi.is"
        # Búa til nýja vefsíðu á vefþjóninn
        New-Website -Name "$userN.tskloi.is" -HostHeader "$userN.tskloi.is" -PhysicalPath "C:\inetpub\wwwroot\$userN.tskloi.is\"  
        
        #sæki núverandi réttindi
        $rettindi = Get-Acl -Path C:\inetpub\wwwroot\$userN.tskloi.is
        #bý til þau réttindi sem ég ætla að bæta við möppuna
        $nyrettindi = New-Object System.Security.AccessControl.FileSystemAccessRule($($env:userdomain + "\" + $userN),"Modify","Allow")
        $nyrettindi2 = New-Object System.Security.AccessControl.FileSystemAccessRule($($env:userdomain + "\ "),"Modify","Allow")
        #Hver á að fá réttindin, hvaða réttindi á viðkomandi að fá, erum við að leyfa eða banna (allow eða deny)
        #bæti nýju réttindunum við þau sem ég sótti áðan
        $rettindi.AddAccessRule($nyrettindi)
        $rettindi.AddAccessRule($nyrettindi2)
        #Set réttindin aftur á möppuna
        Set-Acl -Path C:\inetpub\wwwroot\$userN.tskloi.is $rettindi                   
    }

    function buildSql{

    }