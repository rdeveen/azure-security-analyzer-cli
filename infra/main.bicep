targetScope = 'resourceGroup'

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'nsg-empty'
  properties: {
    securityRules: []
  }
}

resource nsgWithAllowAll 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'nsg-allow-all'
  properties: {
    securityRules: [
      {
        name: 'AllowAllInbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
        }
      }
      {
        name: 'AllowAllOutbound'
        properties: {
          priority: 200
          direction: 'Outbound'
          access: 'Allow'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}
