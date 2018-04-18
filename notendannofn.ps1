foreach($s in $nemendur){
    if($s.Hlutverk -eq "Kennarar") {
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
    'Samaccountname'= $n
    }
}
foreach($s in $nemendur){
    if($s.Hlutverk -eq "Nemendur") {
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
    'Samaccountname'= $a
    }

}