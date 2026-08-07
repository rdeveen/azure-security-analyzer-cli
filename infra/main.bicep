targetScope = 'resourceGroup'

@description('The location for all resources.')
param location string = resourceGroup().location

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'nsg-empty'
  location: location
  properties: {
    securityRules: []
  }
}

resource nsgWithAllowAll 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'nsg-allow-all'
  location: location
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

resource nsgNic1 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'nsg-nic-1'
  location: location
  properties: {
    securityRules: []
  }
}

resource nsgNic2 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'nsg-nic-2'
  location: location
  properties: {
    securityRules: []
  }
}

resource nsgSubnet1 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'nsg-subnet-1'
  location: location
  properties: {
    securityRules: []
  }
}

resource nsgSubnet2 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'nsg-subnet-2'
  location: location
  properties: {
    securityRules: []
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {
  name: 'vnet-main'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
  }
}

resource subnet1 'Microsoft.Network/virtualNetworks/subnets@2023-05-01' = {
  parent: vnet
  name: 'subnet-1'
  properties: {
    addressPrefix: '10.0.1.0/24'
    networkSecurityGroup: {
      id: nsgSubnet1.id
    }
  }
}

resource subnet2 'Microsoft.Network/virtualNetworks/subnets@2023-05-01' = {
  parent: vnet
  name: 'subnet-2'
  properties: {
    addressPrefix: '10.0.2.0/24'
    networkSecurityGroup: {
      id: nsgSubnet2.id
    }
  }
  dependsOn: [
    subnet1
  ]
}

resource nic1 'Microsoft.Network/networkInterfaces@2023-05-01' = {
  name: 'nic-1'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: subnet1.id
          }
        }
      }
    ]
    networkSecurityGroup: {
      id: nsgNic1.id
    }
  }
}

resource nic2 'Microsoft.Network/networkInterfaces@2023-05-01' = {
  name: 'nic-2'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: subnet2.id
          }
        }
      }
    ]
    networkSecurityGroup: {
      id: nsgNic2.id
    }
  }
}
