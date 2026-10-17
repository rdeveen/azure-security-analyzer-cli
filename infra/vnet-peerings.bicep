param location string

resource vnetPeeringTestSource 'Microsoft.Network/virtualNetworks@2025-07-01' = {
  name: 'vnet-peering-test-source'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.1.0.0/16'
      ]
    }
  }
}

resource vnetPeeringTestRemote 'Microsoft.Network/virtualNetworks@2025-07-01' = {
  name: 'vnet-peering-test-remote'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.2.0.0/16'
      ]
    }
  }
}

@description('Two-way virtual network peering between source and remote virtual networks')
resource vnetPeeringTestSourceToRemote 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2024-05-01' = {
  parent: vnetPeeringTestSource
  name: 'source-to-remote'
  properties: {
    remoteVirtualNetwork: {
      id: vnetPeeringTestRemote.id
    }
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
  }
}

@description('Two-way virtual network peering between remote and source virtual networks')
resource vnetPeeringTestRemoteToSource 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2024-05-01' = {
  parent: vnetPeeringTestRemote
  name: 'remote-to-source'
  properties: {
    remoteVirtualNetwork: {
      id: vnetPeeringTestSource.id
    }
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
  }
}

resource vnetPeeringTestAsymmetricSource 'Microsoft.Network/virtualNetworks@2025-07-01' = {
  name: 'vnet-peering-test-asymmetric-source'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.3.0.0/16'
      ]
    }
  }
}

resource vnetPeeringTestAsymmetricRemote 'Microsoft.Network/virtualNetworks@2025-07-01' = {
  name: 'vnet-peering-test-asymmetric-remote'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.4.0.0/16'
      ]
    }
  }
}

@description('One-way virtual network peering from source to remote virtual network')
resource vnetPeeringTestAsymmetricSourceToRemote 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2024-05-01' = {
  parent: vnetPeeringTestAsymmetricSource
  name: 'asymmetric-source-to-remote'
  properties: {
    remoteVirtualNetwork: {
      id: vnetPeeringTestAsymmetricRemote.id
    }
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
  }
}

resource vnetPeeringTestNetworkAccessSource 'Microsoft.Network/virtualNetworks@2025-07-01' = {
  name: 'vnet-peering-test-network-access-source'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.1.0.0/16'
      ]
    }
  }
}

resource vnetPeeringTestNetworkAccessRemote 'Microsoft.Network/virtualNetworks@2025-07-01' = {
  name: 'vnet-peering-test-network-access-remote'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.2.0.0/16'
      ]
    }
  }
}
 

@description('Disallow virtual network access from source to remote virtual network peering')
resource vnetPeeringTestDisallowVirtualNetworkAccess 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2024-05-01' = {
  parent: vnetPeeringTestNetworkAccessSource
  name: 'disallow-virtual-network-access'
  properties: {
    remoteVirtualNetwork: {
      id: vnetPeeringTestNetworkAccessRemote.id
    }
    allowVirtualNetworkAccess: false
    allowForwardedTraffic: true
  }
}

@description('Disallow virtual network access from remote to source virtual network peering')
resource vnetPeeringTestDisallowVirtualNetworkAccessRemote 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2024-05-01' = {
  parent: vnetPeeringTestNetworkAccessRemote
  name: 'disallow-virtual-network-access'
  properties: {
    remoteVirtualNetwork: {
      id: vnetPeeringTestNetworkAccessSource.id
    }
    allowVirtualNetworkAccess: false
    allowForwardedTraffic: true
  }
}
