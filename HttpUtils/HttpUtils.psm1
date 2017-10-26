Function Get-QueryParameterValue {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    ) 
    [System.Web.HttpUtility]::ParseQueryString($Request.Url.query)[$Name]
}

Function Get-LocalPath {
    $Request.Url.LocalPath
}

Function Get-HttpMethod {
    $Request.HttpMethod
}

Function Test-HttpMethod {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("GET","POST","PUT","DELETE","HEAD","TRACE","CONNECT")]
        [string]$Method
    )
    $Request.HttpMethod -eq $Method
}
#Export-ModuleMember -Function @("Get-QueryParameter","Get-LocalPath","Get-HttpMethod","Test-HttpMethod")
Export-ModuleMember -Function *
