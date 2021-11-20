$import = Get-Content .\json.json
$import = Get-Content .\json.json | ConvertFrom-Json
$import | Get-Member
$import.members
$import.members.age
