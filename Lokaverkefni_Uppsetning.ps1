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

$notendur = Import-Csv .\lokaverk_notendur.csv
##############################################
#Groups
    foreach ($s in $notendur){            
        $skoli = $s.Skoli
        $skolOUpath = (Get-ADOrganizationalUnit -Filter { name -like $skoli }).DistinguishedName
        $hlutverk = $s.Hlutverk
        $hlutOUpath = (Get-ADOrganizationalUnit -Filter { name -like $hlutverk }).DistinguishedName
        $braut = $s.Braut
        $brautOUpath = (Get-ADOrganizationalUnit -Filter { name -like $braut }).DistinguishedName
        ##############################################
        ## Búa til Nemendu OU.
        if($hlutverk = "Nemendur"){
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
        if(-not($hlutverk = "Nemendur")){
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
        #Create Sql

    }
