# get device code

#$ClientID = '293f277b-ae2b-4913-8973-e4be8367d161'
$clientID = '6222f1cd-52dd-4316-ae95-b74149da7b3d'
$tenantID = 'c2567084-31ef-4a6e-bb65-9fda9cbb7941'
$scope = "https://management.azure.com/user_impersonation"

$subscriptionId = "fdeaf022-a889-423d-a9d4-1b913d1c3bbe"

$token = ''

if ($token -eq '')
{
    $body = @{
        'client_id' = $clientId
        'scope'  = $scope
    }
    $DeviceCodeRequest = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/devicecode" -Method POST -Body $body

    Write-Host $DeviceCodeRequest.message -ForegroundColor Yellow
    Write-Host -NoNewLine 'Press any key to continue...';
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');

    # token request

    $body   = @{
        'grant_type' = "urn:ietf:params:oauth:grant-type:device_code"
        'code'       = $DeviceCodeRequest.device_code
        'client_id'  = $clientId
    }
    $TokenRequest = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body $body

    $token = $TokenRequest.access_token
    Write-Host $token
    Write-Host (Get-Date).AddSeconds($TokenRequest.expires_in)
}



$apiVersionParam = "api-version=2020-09-01"

$policyUri = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Authorization/policyAssignments?$apiVersionParam"
#$policyUri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/apitest/providers/Microsoft.Authorization/policyAssignments?$apiVersionParam"

$headers = @{
    'Host' = 'management.azure.com'
    'Content-Type' = 'application/json'
    'Authorization' = "Bearer $token"
    }
$policyDefinitions = Invoke-RestMethod -Uri $policyUri  -Method GET -Headers $headers 

$allPolicies = [System.Collections.ArrayList]@()

Foreach ($definition in $policyDefinitions.value)
{
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

$allPolicies 

$allPolicies | Export-Csv -Path .\results.csv -NoTypeInformation

