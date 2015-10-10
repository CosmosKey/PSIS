<#
.SYNOPSIS
   Start the PSWebServer

.DESCRIPTION
   Start the PSWebServer. 
   
   PSWebServer is a very lightweight WebServer written entierly in PowerShell.
   PSWebServer enables the user to very quickly expose HTML or simple JSON endpoints to the network.

    The -ProcessRequest parameter takes a scriptblock which is executed on every request.

    There are four automatic variables avaiable to the user in ProcessRequest.
    Listed here with their associated types.

        $Context   [System.Net.HttpListenerContext]
        $User      [System.Security.Principal.GenericPrincipal]
        $Request   [System.Net.HttpListenerRequest]
        $Response  [System.Net.HttpListenerResponse]

    The $Request object is extended with three NoteProperty members. 

        $Request.RequestBody    The RequestBody contains a string representation of the inputstream
                                This could be JSON objects being sent in with a PUT or POST request.
        $Request.RequestBuffer  The RequestBuffer is the raw [byte[]] buffer of the inputstream
        $Request.RequestObject  The RequestObject property is the RequestBody deserialized as JSON 
                                to powershell objects

    The $Response object is extended with one NoteProperty member. 

        $Response.ResponseFile  If this is set to a valid filename. Then PSWebServer will send the file 
                                back to the calling agent.

    The $Context object is extended with one NoteProperty member. 

        $Context.Session  This is a server side session object for handling session variables of a connection.
                          A timer is creating an event every -SessionLifespan seconds in which it purges expired 
                          sessions. The variable $Session references the same object.


    Write-Verbose is not the original cmdlet in the context of the ProcessRequest ScriptBlock. It is an overlayed 
    function which talks back to the main thread using a synchronized queue object which in its turn outputs the 
    messages using the original Write-Verbose. The function in the ProcessRequest ScriptBlock is called the same 
    for convinience. This enables us to output debugging info to the screen when using the -Verbose switch.

.PARAMETER URL
    Specifies the listening URL. Default is http://*:8080/. See the System.Net.HttpListener documentation for details
    of the format.

.PARAMETER AuthenticationSchemes
    Specifies the authentication scheme. Default is Negotiate (kerberos). The "none" value is not supported, 
    use "Anonymous" instead.

.PARAMETER RunspacesCount
    Specifies the number of PowerShell Runspaces used in the RunspacePool internally. More RunSpaces allows 
    for more concurrent requests. Default is 4.

.PARAMETER ProcessRequest
    This is the scriptblock which is executed per request.

    If the $response.ResponseFile property has been set to a file. Then PSWebServer will send that file to the 
    calling agent.

    If the ScriptBlock returns a single string then that will be assumed to be html.
    The string will then be sent directly to the response stream as "text/html".

    If the ScriptBlock returns other PS objects then these are converted to JSON objects and written to the 
    response stream as JSON with the "application/json" contenttype.

.PARAMETER Modules
    A list of modules to be loaded for the internal runspacepool.

.PARAMETER Impersonate
    Use to impersonate the calling user. PSWebServer enters impersonation on the powershell thread befoew the 
    ProcessRequest scriptblock is executed and it reverts back the impersonation just after.

.PARAMETER SkipReadingInputstream
    Skip parsing the inputstream. This leaves the inputstream untouched for explicit processing of 
    $request.inputstream.

.PARAMETER SessionLifespan
    The SessionLifespan parameter defines how long a session lives for and destroys the session and 
    the session variables after the specified time. The session hastable of session variables is accessed 
    through the $Context.Session property.

    Default value is 30 minutes and the variable takes a [timespan] object.

.EXAMPLE
    "<html><body>Hello</body></html>" | out-file "c:\ps\index.html"
    Start-PSWebServer -URL "http://*:8087/" -AuthenticationSchemes negotiate -ProcessRequest {
        if($Request.rawurl -eq "/index.html"){
            $Response.ResponseFile = "c:\ps\index.html"
        } else {
            $params = [System.Web.HttpUtility]::ParseQueryString($request.Url.Query)
            Write-Verbose "Searching for user: $($params["user"])"
            if($params -and $params["user"]) {
                Get-ADUser -Identity $params["user"]
            }
        }
    } -Verbose -Impersonate -Modules "ActiveDirectory"

    This is an example of binding the webserver to port 8087 with the negotiate (kerberos) authentication scheme.
    The -Verbose switch is used to output messages on the screen for troubleshooting. There is an added property
    to the $response object called ResponseFile. If the $response.ResponseFile property is set to a valid file, then
    PSWebServer will send the file to the calling agent. Further more, PSWebServer runs with impersonation enabled. 

    The -Modules parameter specifies modules to be loaded for the runspaces in the internal runspacepool.

    The sample maps /index.html to the c:\ps\index.html file.

    If a URL such as http://servername:8087/?user=administrator is requested then the sample code will extract the 
    administrator value and pass this to Get-ADUser. The returning object will then be JSONified and sent to the 
    calling agent.

.EXAMPLE

    Start-PSWebServer -URL "https://*:443/" -AuthenticationSchemes Basic -ProcessRequest {
        "<html><body>Hello $($user.identity.name)</body></html>"
    } -Verbose 

    Here we bind PSWebServer to SSL on port 443. AuthenticationScheme is set to basic authentication.
    We use the automatic $user variable to get the WindowsIdentity object and its Name property 
    this gives us the username of the calling user. A certificate needs to be deplyed to the machine in 
    order for this binding to work.

.EXAMPLE 

    Start-PSWebServer -URL "http://*:8087/" -AuthenticationSchemes negotiate -ProcessRequest {
        Write-Verbose $request.RequestBody
        $request.RequestObject.Sequence+=5
        $request.RequestObject
    } -Verbose -Impersonate

    This example assumes a JSON object with a Sequence property which is an array being sent in through
    a POST or PUT request.
     
    The sample acts on the JSON deserialized powershell object available in the $request.RequestObject property
    It adds 5 to the array and then returns the powershell object to the pipeline.

        If the following client code is used:
        $data = [pscustomobject]@{
            Sequence = @(1,2,3,4)
            Strings = @("Orange","yellow","black")
        }
        $postData = $data | ConvertTo-Json
        Start-RestMethod -Method post -Uri 'http://localhost:8087/json' -UseDefaultCredentials -Body $postData | ConvertTo-Json

    Then the resulting JSON will have had the number 5 added to the Sequence array.

.NOTES

    Hello, my name is Johan Åkerström. I'm the author of PSWebServer.

    Please visit my blog at:

        http://blog.cosmoskey.com

    If you need to email me then do so on:

        mailto:johan.akerstrom {at} cosmoskey com

    Visit this GitHub project at:

        http://github.com/CosmosKey/PSWebServer

    Enjoy!

#>
Function Start-PSWebServer {
    [cmdletbinding()]
    param(
        [string]$URL = "http://*:8084/",
        [System.Net.AuthenticationSchemes]$AuthenticationSchemes = "Negotiate",
        [int]$RunspacesCount = 4,
        [scriptblock]$ProcessRequest={},
        [string[]]$Modules,
        [timespan]$SessionLifespan=$(New-TimeSpan -Minutes 30),
        [Switch]$SkipReadingInputstream,
        [Switch]$Impersonate
    )

    if($Impersonation -and ($AuthenticationSchemes -eq "none" -or $AuthenticationSchemes -eq "anonymous")){
        throw "Impersonation can't be used with the None or Anonymous authenticationScheme."
    }

    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($url)
    $listener.AuthenticationSchemes = $authenticationSchemes
    $listener.Start()
    # todo sort out path
    #$httpUtilsPath = Join-Path $PSScriptRoot "HttpUtils\HttpUtils.psm1"
    $httpUtilsPath = Join-Path $pwd "HttpUtils\HttpUtils.psm1"
    $InitialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
    $InitialSessionState.ImportPSModule($httpUtilsPath)
    foreach($module in $Modules) {
        [void]$InitialSessionState.ImportPSModule($module)
    }

    Write-Verbose "Starting up a runspace pool of $RunspacesCount runspaces"
    $pool = [runspacefactory]::CreateRunspacePool($InitialSessionState)
    [void]$pool.SetMaxRunspaces($RunspacesCount)
    $pool.Open()

    $VerboseMessageQueue = [System.Collections.Queue]::Synchronized((New-Object Collections.Queue))
    $SessionStates = [hashtable]::Synchronized((New-Object Hashtable))
    $sessionStateTimer = New-Object System.Timers.Timer
    $messageData = [pscustomobject]@{
        SessionStates = $sessionStates
        VerboseMessageQueue = $VerboseMessageQueue
    }
    $job = Register-ObjectEvent `
        -InputObject $sessionStateTimer `
        -EventName Elapsed `
        -SourceIdentifier "SessionStateManager" `
        -MessageData $messageData `
        -Action {
        $sessionStates = $event.MessageData.SessionStates
        $VerboseMessageQueue = $event.MessageData.VerboseMessageQueue 
        $expiredSessions = $sessionStates.Values | ? {$_.Cookie.Expired}
        foreach($expiredSession in $expiredSessions) {
            $sessionGuid = $expiredSession.Cookie.Value
            $VerboseMessageQueue.Enqueue("Removing session $sessionGuid")
            [void]$SessionStates.Remove($sessionGuid)
        }
    }
    $sessionStateTimer.Interval = 1000 * 1 # Cleanup sessions every 30 seconds
    $sessionStateTimer.Start()
    $RequestListener = {
        param($config)
        $config.VerboseMessageQueue.Enqueue("Waiting for request")
        $psWorker = [powershell]::Create() # $config.InitialSessionState)
        $config.Context = $config.listener.GetContext()
        $psWorker.RunspacePool = $config.Pool
        [void]$psWorker.AddScript($config.RequestHandler.ToString())
        [void]$psWorker.AddArgument($config)
        [void]$psWorker.BeginInvoke()
    }
    $RequestHandler = {
        param($config)
        Function Write-Verbose {
            param($message)
            $config.VerboseMessageQueue.Enqueue("$message")
        }
        $context  = $config.context
        $Request  = $context.Request
        $Response = $context.Response
        $User     = $context.User

        if(!$request.Cookies["SessionID"]) {
            $guid = [guid]::NewGuid().Guid
            Write-Verbose "Creating session $guid"
            $sessionCookie = New-Object System.Net.Cookie "SessionID",$guid,"/"
            $sessionCookie.Expires = [datetime]::Now.Add($config.SessionLifespan)            
            $sessionState = [pscustomobject]@{
                Cookie = $sessionCookie
                Variables = @{}
            }
            $config.SessionStates.Add($guid,$sessionState)
            $response.SetCookie($sessionCookie)
        } else {
            $requestCookie = $request.Cookies["SessionID"]
            $guid = $requestCookie.Value
            $sessionState = $config.SessionStates[$guid]
            if($sessionState){
                Write-Verbose "Request for session $guid"
                $sessionCookie = $sessionState.Cookie
                $sessionCookie.Expires = [datetime]::Now.Add($SessionLifespan)
            } else {
                $guid = [guid]::NewGuid().Guid
                Write-Verbose "Creating session $guid"
                $sessionCookie = New-Object System.Net.Cookie "SessionID",$guid,"/"
                $sessionCookie.Expires = [datetime]::Now.Add($SessionLifespan)
                $sessionState = [pscustomobject]@{
                    Cookie = $sessionCookie
                    Variables = @{}
                }
            }
            $config.SessionStates[$guid] = $sessionState
            $response.SetCookie($sessionCookie)
        }
        $Session = $config.SessionStates[$guid].Variables
        $context | Add-Member -Name Session -Value $Session -MemberType NoteProperty -Force
        
        $clientAddress = "{0}:{1}" -f $Request.RemoteEndPoint.Address,$Request.RemoteEndPoint.Port
        Write-Verbose "Client connecting from $clientAddress"
        if($User.Identity){
            Write-Verbose "User $($User.Identity.Name) sent a request"
        }
        
        if(!$config.SkipReadingInputstream){
            Write-Verbose "Reading request body"
            $length = $Request.ContentLength64
            $buffer = New-Object "byte[]" $length
            [void]$Request.InputStream.Read($buffer,0,$length)
            $requestBody = [System.Text.Encoding]::ASCII.GetString($buffer)
            $requestObject = $requestBody | ConvertFrom-Json
            $context.Request  | Add-Member -Name RequestBody -MemberType NoteProperty -Value $requestBody -Force
            $context.Request  | Add-Member -Name RequestBuffer -MemberType NoteProperty -Value $buffer-Force
            $context.Request  | Add-Member -Name RequestObject -MemberType NoteProperty -Value $requestObject -Force
        }
        $context.Response | Add-Member -Name ResponseFile -MemberType NoteProperty -Value $null -Force
        try {
            if($config.Impersonate){
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                Write-Verbose "Impersonate as $($User.Identity.Name) from $currentUser."
                $ImpersonationContext = $User.Identity.Impersonate()
            } 
            $ProcessRequest = [scriptblock]::Create($config.ProcessRequest.tostring())
            Write-Verbose "Executing ProcessRequest"
            $result = .$ProcessRequest $context
            $config.SessionStates[$guid].Variables = $context.Session
            if($context.Response.ResponseFile) {
                Write-Verbose "The ResponseFile property was set"
                Write-Verbose "Sending file $($context.Response.ResponseFile)"
                $buffer = [System.IO.File]::ReadAllBytes($context.Response.ResponseFile)
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            } elseif($context.Response.ContentLength64 -eq 0){
                if($result -ne $null) {
                    if($result -is [string]){
                        Write-Verbose "A [string] object was returned. Writing it directly to the response stream."
                        $buffer = [System.Text.Encoding]::ASCII.GetBytes($result)
                        $response.ContentLength64 = $buffer.Length
                        $response.OutputStream.Write($buffer, 0, $buffer.Length)
                        if(!$response.contenttype) {
                            $response.contenttype = "text/html"
                        }
                    } else {
                        Write-Verbose "Converting PS Objects into JSON objects"
                        $jsonResponse = $result | ConvertTo-Json
                        $buffer = [System.Text.Encoding]::ASCII.GetBytes($jsonResponse)
                        $response.ContentLength64 = $buffer.Length
                        $response.OutputStream.Write($buffer, 0, $buffer.Length)
                        if(!$response.contenttype) {
                            $response.contenttype = "application/json"
                        }
                    }
                }
            }
        } catch {
            $Context.Response.StatusRequestHandler = "500"
        } finally {
            if($config.Impersonate){
                Write-Verbose "Undo impersonation as $($User.Identity.Name) reverting back to $currentUser"
                $ImpersonationContext.Undo()
            } 
            $response.close()
        }

    }
   
    try {
        Write-Verbose "Server listening on $url"
        while ($listener.IsListening)
        {
            if($iasync -eq $null -or $iasync.IsCompleted) {
                $obj = New-Object object
                $ps = [powershell]::Create() # $InitialSessionState)
                $ps.RunspacePool = $pool
                $config = [pscustomobject]@{
                    Listener = $listener
                    Pool = $pool
                    VerboseMessageQueue = $VerboseMessageQueue
                    Requesthandler = $Requesthandler
                    ProcessRequest = $ProcessRequest
                    InitialSessionState = $InitialSessionState
                    Impersonate = $Impersonate
                    Context = $null
                    SkipReadingInputstream = $SkipReadingInputstream
                    SessionStates = $SessionStates
                    SessionLifespan = $SessionLifespan
                }
                [void]$ps.AddScript($RequestListener.ToString())
                [void]$ps.AddArgument($config)
                $iasync = $ps.BeginInvoke()
            }
            while($VerboseMessageQueue.count -gt 0){
                Write-Verbose $VerboseMessageQueue.Dequeue()
            }                 
            Start-Sleep -Milliseconds 30
        }
    } finally {
        Write-Verbose "Closing down server"
        $listener.Stop()
        $listener.Close()
        $sessionStateTimer.Stop()
        Unregister-Event -SourceIdentifier "SessionStateManager"
    }
}
#Export-ModuleMember -Function "Start-PSWebServer"



