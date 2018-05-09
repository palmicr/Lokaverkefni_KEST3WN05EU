#import SQL Server module


function buildSql{
        param(
            [Parameter(Mandatory=$true, HelpMessage="Sláðu inn Noteindarnafnið")]
            [string]$username
        )

    Import-Module SQLPS -DisableNameChecking

    $TBnotaindur = (Get-ADUser -Properties "Samaccountname" -SearchBase "OU=Tölvubraut,OU=Upplýsingatækniskólinn,OU=Nemendur,OU=Notendur, DC=tskloi19, DC=local" -Filter *).Samaccountname
    $TBkennarar = (Get-ADGroup -Identity "Tölvubraut_Kennarar").Name
    
        $instanceName = "WIN3A-10"
        $dbUserName = $username
        $password = "pass.123"
        $databaseName = $username
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