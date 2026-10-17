targetScope = 'resourceGroup'

@description('The location for all resources.')
param location string = resourceGroup().location

module nsg 'nsg.bicep' = {
  name: 'nsg-test'
  params: {
    location: location
  }
}

module firewall 'firewall.bicep' = {
  name: 'firewall-test'
  params: {
    location: location
  }
}

module virtualNetworkPeering 'vnet-peerings.bicep' = {
  name: 'virtual-network-peering-test'
  params: {
    location: location
  }
}
