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

resource nsgNicEmpty 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'nsg-nic-empty'
  location: location
  properties: {
    securityRules: []
  }
}

resource nsgNicAllowAll 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'nsg-nic-allow-all'
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

resource nsgSubnetEmpty 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'nsg-subnet-empty'
  location: location
  properties: {
    securityRules: []
  }
}

resource nsgSubnetAllowAll 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'nsg-subnet-allow-all'
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

resource vnetSecurityTest 'Microsoft.Network/virtualNetworks@2023-05-01' = {
  name: 'vnet-security-test'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
  }
}

resource subnetNsgEmpty 'Microsoft.Network/virtualNetworks/subnets@2023-05-01' = {
  parent: vnetSecurityTest
  name: 'subnet-nsg-empty'
  properties: {
    addressPrefix: '10.0.1.0/24'
    networkSecurityGroup: {
      id: nsgSubnetEmpty.id
    }
  }
}

resource subnetNsgAllowAll 'Microsoft.Network/virtualNetworks/subnets@2023-05-01' = {
  parent: vnetSecurityTest
  name: 'subnet-nsg-allow-all'
  properties: {
    addressPrefix: '10.0.2.0/24'
    networkSecurityGroup: {
      id: nsgSubnetAllowAll.id
    }
  }
  dependsOn: [
    subnetNsgEmpty
  ]
}

resource nicNsgEmpty 'Microsoft.Network/networkInterfaces@2023-05-01' = {
  name: 'nic-nsg-empty'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: subnetNsgEmpty.id
          }
        }
      }
    ]
    networkSecurityGroup: {
      id: nsgNicEmpty.id
    }
  }
}

resource nicNsgAllowAll 'Microsoft.Network/networkInterfaces@2023-05-01' = {
  name: 'nic-nsg-allow-all'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: subnetNsgAllowAll.id
          }
        }
      }
    ]
    networkSecurityGroup: {
      id: nsgNicAllowAll.id
    }
  }
}
