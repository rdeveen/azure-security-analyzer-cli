targetScope = 'resourceGroup'

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'nsg-empty'
  properties: {
    securityRules: []
  }
}
