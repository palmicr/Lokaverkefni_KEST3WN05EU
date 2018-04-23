##############################################
#Groups
$nemendur = Import-Csv .\Downloads\lokaverk_notendur.csv
    foreach ($s in $notendur){            
        $skoli = $s.Skoli
        $skolOUpath = (Get-ADOrganizationalUnit -Filter { name -like $skoli }).DistinguishedName
        $hlutverk = $s.Hlutverk
        $hlutOUpath = (Get-ADOrganizationalUnit -Filter { name -like $hlutverk }).DistinguishedName
        $braut = $s.Braut
        $brautOUpath = (Get-ADOrganizationalUnit -Filter { name -like $braut }).DistinguishedName
        ##############################################
        ## Búa til Nemendu OU.
        if($hlutverk -eq "Nemendur"){
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
                if(-not(Get-ADUser -Filter { SamAccountName -like $n })){
                        $a = $($a + $teljari)
                }
                else{
                    $finnanotandi = Get-ADUser -Filter * -SearchBase $("SamAccountName =", $a)
                    foreach($fannst in $finnanotandi.SamAccountName){
                        $teljari++
                    }
                    $a = $($a + $teljari)
                    } 
                $username = $a;
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
                $hashUser = @{
                    'Name'= $s.Nafn;
                    'Displayname'= $s.Nafn;
                    'Title' = $stada;
                    'Givenname' = $s.Nafn.Split(" ")[0,-1];
                    'Surname'= $s.Nafn.Split(" ")[-1];
                    'Samaccountname'= $username;
                    'UserPrincipalName' = $($a + "@" + $env:USERDNSDOMAIN);
                    'Path'= $("ou=" + $braut + "," + $brautOUpath);
                    'AccountPassword'= (ConvertTo-SecureString -AsPlainText "pass.123" -Force);
                    'Enabled' = $true;
                 }
                 $hashUser

}
