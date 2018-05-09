function 1-time-groups {
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



############################################################################################
    function buildSite{
                
    }


############################################################################################
#import SQL Server module
Import-Module SQLPS -DisableNameChecking

function buildSql{

    $TBnotaindur = (Get-ADUser -Properties "Samaccountname" -SearchBase "OU=Tölvubraut,OU=Upplýsingatækniskólinn,OU=Nemendur,OU=Notendur, DC=tskloi19, DC=local" -Filter *).Samaccountname
    $TBkennarar = (Get-ADGroup -Identity "Tölvubraut_Kennarar").Name
    foreach ($n in $TBnotaindur){

        $instanceName = "WIN3A-10"
        $dbUserName = $n
        $password = "pass.123"
        $databaseName = $n
        $roleName = "db_owner"
        

        $server = new-Object Microsoft.SqlServer.Management.Smo.Server("WIN3A-10")
        $db = New-Object Microsoft.SqlServer.Management.Smo.Database($server, $databaseName)
        $db.Create()

        $login = new-object Microsoft.SqlServer.Management.Smo.Login("WIN3A-10", $dbUserName)
        $login.LoginType = 'WindowsUser'
        $login.PasswordPolicyEnforced = $false
        #$login.PasswordExpirationEnabled = $false
        #$login.Create($password)

        $server = new-Object Microsoft.SqlServer.Management.Smo.Server("WIN3A-10")
        $db = New-Object Microsoft.SqlServer.Management.Smo.Database
        $db = $server.Databases.Item($databaseName)
        
        $Q = "exec sp_addrolemember @rolename = '$roleName', @membername = '${env:UserDomain}\$TBkennarar'" 

        Invoke-Sqlcmd -ServerInstance "WIN3A-10" -Database $databaseName -Username $dbUserName -Password $password 
        Invoke-Sqlcmd -ServerInstance "WIN3A-10" -Database $databaseName -Query "EXEC sp_changedbowner '$dbUserName'" 
        Invoke-Sqlcmd -ServerInstance "WIN3A-10" -Database $databaseName -Query $Q       
    }
}