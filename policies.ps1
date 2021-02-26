<#
Use the Azure Resource API to retrieve a list of policy assignments for a subscription.
#>

<#
Get Authentication Token from AAD using the device code flow. Note that for convienvience in running and testing the script
the token is stored locally - this is not recommended in shared environments.
#>

# update with the appropriate Ids
$subscriptionId = ''
$clientID = ''
$tenantID = ''

$scope = "https://management.azure.com/user_impersonation"

$token = ''

$tokenFileExists = Test-Path .\token.clicml

if ($tokenFileExists)
{
    $tokenFile = Import-Clixml .\token.clicml

    if ($tokenFile.expiry -gt (Get-Date))
    {
        Write-Host "Using existing token, expiry $($tokenFile.expiry)"
        $token = $tokenFile.token
    }
}

if ($token -eq '')
{
    Write-Host "New token required"
    $body = @{
        'client_id' = $clientId
        'scope'  = $scope
    }
    $DeviceCodeRequest = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/devicecode" -Method POST -Body $body

    Write-Host $DeviceCodeRequest.message -ForegroundColor Yellow
    Write-Host 'Press any key when browser authentication has completed';
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');

    # token request

    $body   = @{
        'grant_type' = "urn:ietf:params:oauth:grant-type:device_code"
        'code'       = $DeviceCodeRequest.device_code
        'client_id'  = $clientId
    }
    $TokenRequest = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body $body

    $token = $TokenRequest.access_token
    $tokenExpiry = (Get-Date).AddSeconds($TokenRequest.expires_in)

    $tokenFile = [pscustomobject]@{
        token = $token
        expiry = $tokenExpiry
    }
    $tokenFile | Export-Clixml token.clicml
}

### Get Policies


$apiVersionParam = "api-version=2020-09-01"

# Get poliie assignemnts by subscription

$policyUri = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Authorization/policyAssignments?$apiVersionParam"

$headers = @{
    'Host' = 'management.azure.com'
    'Content-Type' = 'application/json'
    'Authorization' = "Bearer $token"
    }
$policyDefinitions = Invoke-RestMethod -Uri $policyUri  -Method GET -Headers $headers 

$allPolicies = [System.Collections.ArrayList]@()

Foreach ($definition in $policyDefinitions.value)
{
    # if the policy assigment is an initiative, get all the polcicies in the set
    if ($definition.properties.policyDefinitionId -Match "policySetDefinitions")
    {       
        $policySetDefinitions = Invoke-RestMethod -Uri "https://management.azure.com$($definition.properties.policyDefinitionId)?$apiVersionParam" -Method GET -Headers $headers 

        foreach ($policySetDefinition in $policySetDefinitions.properties.policyDefinitions)
        {
            $policyDefinition = Invoke-RestMethod -Uri "https://management.azure.com$($policySetDefinition.policyDefinitionId)?$apiVersionParam" -Method GET -Headers $headers 

            $row = [pscustomobject]@{
                scope = $definition.properties.scope
                displayName = $policyDefinition.properties.displayName
                effect = $policyDefinition.properties.parameters.effect.defaultValue
                policyDefinitionId = $definition.properties.policyDefinitionId
            }

            $null = $allPolicies.Add($row)
        }

    }
    else
    {
        $policyDefinition = Invoke-RestMethod -Uri "https://management.azure.com$($definition.properties.policyDefinitionId)?$apiVersionParam" -Method GET -Headers $headers 

        $row = [pscustomobject]@{
            scope = $definition.properties.scope
            displayName = $definition.properties.displayName
            effect = $policyDefinition.properties.policyRule.then.effect
            policyDefinitionId = $definition.properties.policyDefinitionId
        }

        $null = $allPolicies.Add($row)
    }
}

$allPolicies | Export-Csv -Path .\results.csv -NoTypeInformation

