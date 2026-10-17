param location string

@description('This Firewall Policy is intentionally unattached, has intrusion detection disabled, and has no rule collection groups.')
resource firewallPolicyIdpsOffNoRules 'Microsoft.Network/firewallPolicies@2024-05-01' = {
  name: 'fp-idps-off-no-rules'
  location: location
  properties: {
    sku: {
      tier: 'Premium'
    }
    threatIntelMode: 'Alert'
    intrusionDetection: {
      mode: 'Off'
    }
  }
}

@description('This Firewall Policy is intentionally unattached and contains an allow-all network rule for analyzer validation without deploying an Azure Firewall.')
resource firewallPolicyAllowAll 'Microsoft.Network/firewallPolicies@2024-05-01' = {
  name: 'fp-alert-allow-all'
  location: location
  properties: {
    sku: {
      tier: 'Premium'
    }
    threatIntelMode: 'Alert'
    intrusionDetection: {
      mode: 'Alert'
    }
  }
}

resource firewallPolicyAllowAllRuleCollectionGroup 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2024-05-01' = {
  name: 'DefaultNetworkRuleCollectionGroup'
  parent: firewallPolicyAllowAll
  properties: {
    priority: 200
    ruleCollections: [
      {
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
        name: 'allow-all-collection'
        priority: 100
        action: {
          type: 'Allow'
        }
        rules: [
          {
            ruleType: 'NetworkRule'
            name: 'allow-all-network'
            ipProtocols: [
              'Any'
            ]
            sourceAddresses: [
              '*'
            ]
            destinationAddresses: [
              '*'
            ]
            destinationPorts: [
              '*'
            ]
          }
        ]
      }
    ]
  }
}

@description('This Firewall Policy is intentionally unattached and contains a scoped HTTPS rule so policy analysis can distinguish it from allow-all configurations.')
resource firewallPolicyScopedRule 'Microsoft.Network/firewallPolicies@2024-05-01' = {
  name: 'fp-deny-scoped-rule'
  location: location
  properties: {
    sku: {
      tier: 'Premium'
    }
    threatIntelMode: 'Deny'
    intrusionDetection: {
      mode: 'Deny'
    }
  }
}

resource firewallPolicyScopedRuleCollectionGroup 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2024-05-01' = {
  name: 'DefaultNetworkRuleCollectionGroup'
  parent: firewallPolicyScopedRule
  properties: {
    priority: 200
    ruleCollections: [
      {
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
        name: 'allow-https-only'
        priority: 100
        action: {
          type: 'Allow'
        }
        rules: [
          {
            ruleType: 'NetworkRule'
            name: 'allow-https-outbound'
            ipProtocols: [
              'TCP'
            ]
            sourceAddresses: [
              '10.0.0.0/16'
            ]
            destinationAddresses: [
              '*'
            ]
            destinationPorts: [
              '443'
            ]
          }
        ]
      }
    ]
  }
}

resource vnetSecurityRouteTableFirewallTest 'Microsoft.Network/virtualNetworks@2025-07-01' = {
  name: 'vnet-security-route-table-firewall-test'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
  }
}

@description('This route table has a default route to a firewall and is associated with a subnet.')
resource routeTableFirewall 'Microsoft.Network/routeTables@2025-07-01' = {
  name: 'rt-firewall'
  location: location
  properties: {
    disableBgpRoutePropagation: false
    routes: [
      {
        name: 'default-to-firewall'
        properties: {
          addressPrefix: '0.0.0.0/0'
          nextHopType: 'VirtualAppliance'
          nextHopIpAddress: '10.0.0.4'
        }
      }
    ]
  }
}

@description('This route table has a default route directly to the internet and is not associated with a subnet.')
resource routeTableInternet 'Microsoft.Network/routeTables@2025-07-01' = {
  name: 'rt-internet'
  location: location
  properties: {
    disableBgpRoutePropagation: false
    routes: [
      {
        name: 'default-to-internet'
        properties: {
          addressPrefix: '0.0.0.0/0'
          nextHopType: 'Internet'
        }
      }
    ]
  }
}

@description('This route table has no default route to a firewall and is associated with a subnet.')
resource routeTableMissingFirewall 'Microsoft.Network/routeTables@2025-07-01' = {
  name: 'rt-missing-firewall'
  location: location
  properties: {
    disableBgpRoutePropagation: false
    routes: [
      {
        name: 'internal-route'
        properties: {
          addressPrefix: '10.1.0.0/16'
          nextHopType: 'VirtualNetworkGateway'
        }
      }
    ]
  }
}

resource subnetRouteTableFirewall 'Microsoft.Network/virtualNetworks/subnets@2025-07-01' = {
  parent: vnetSecurityRouteTableFirewallTest
  name: 'subnet-rt-firewall'
  properties: {
    addressPrefix: '10.0.6.0/24'
    routeTable: {
      id: routeTableFirewall.id
    }
  }
}

resource subnetRouteTableMissingFirewall 'Microsoft.Network/virtualNetworks/subnets@2025-07-01' = {
  parent: vnetSecurityRouteTableFirewallTest
  name: 'subnet-rt-missing-firewall'
  properties: {
    addressPrefix: '10.0.7.0/24'
    routeTable: {
      id: routeTableMissingFirewall.id
    }
  }
}
