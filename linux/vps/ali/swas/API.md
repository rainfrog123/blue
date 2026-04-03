# Alibaba Cloud SWAS API Reference

## Instance Management

| API | Description |
|-----|-------------|
| CreateInstances | Create new instances |
| StartInstance / StartInstances | Start instance(s) |
| StopInstance / StopInstances | Stop instance(s) |
| RebootInstance / RebootInstances | Reboot instance(s) |
| ListInstances | List instances |
| ListInstanceStatus | Get instance status |
| UpdateInstanceAttribute | Modify instance settings |
| UpgradeInstance | Upgrade instance plan |
| RenewInstance | Renew subscription |
| ResetSystem | Reinstall OS |
| ListPlans | Available plans |
| ListInstancePlansModification | Upgrade options |
| ListRegions | Available regions |

## Snapshots & Images

| API | Description |
|-----|-------------|
| CreateSnapshot | Create snapshot |
| DeleteSnapshot / DeleteSnapshots | Delete snapshot(s) |
| ListSnapshots | List snapshots |
| UpdateSnapshotAttribute | Modify snapshot settings |
| CreateCustomImage | Create custom image |
| DeleteCustomImage / DeleteCustomImages | Delete image(s) |
| ListCustomImages | List custom images |
| ListImages | List system images |
| ModifyImageShareStatus | Share image settings |
| AddCustomImageShareAccount | Share with account |
| RemoveCustomImageShareAccount | Unshare |
| ListCustomImageShareAccounts | List shared accounts |

## Disks

| API | Description |
|-----|-------------|
| ListDisks | List disks |
| ResetDisk | Reset disk from snapshot |
| UpdateDiskAttribute | Modify disk settings |

## Firewall

| API | Description |
|-----|-------------|
| CreateFirewallRule / CreateFirewallRules | Add firewall rules |
| DeleteFirewallRule / DeleteFirewallRules | Remove rules |
| ListFirewallRules | List rules |
| EnableFirewallRule | Enable rule |
| DisableFirewallRule | Disable rule |
| ModifyFirewallRule | Modify rule |
| CreateFirewallTemplate | Create template |
| ModifyFirewallTemplate | Modify template |
| DeleteFirewallTemplates | Delete templates |
| DescribeFirewallTemplates | List templates |
| CreateFirewallTemplateRules | Add template rules |
| DeleteFirewallTemplateRules | Remove template rules |
| ApplyFirewallTemplate | Apply template to instance |
| DescribeFirewallTemplateApplyResults | Check apply results |

## Remote Access

| API | Description |
|-----|-------------|
| DescribeInstanceVncUrl | Get VNC URL |
| ModifyInstanceVncPassword | Change VNC password |
| LoginInstance | Web terminal login |
| StartTerminalSession | Terminal session |
| DescribeInstancePasswordsSetting | Password settings |

## SSH Keys

| API | Description |
|-----|-------------|
| CreateKeyPair | Create key pair |
| CreateInstanceKeyPair | Create key for instance |
| ImportKeyPair | Import public key |
| DeleteKeyPairs | Delete keys |
| DeleteInstanceKeyPair | Delete instance key |
| AttachKeyPair | Bind key to instance |
| DetachKeyPair | Unbind key |
| ListKeyPairs | List keys |
| DescribeInstanceKeyPair | Get instance key |
| UploadInstanceKeyPair | Upload key |

## Commands (Cloud Assistant)

| API | Description |
|-----|-------------|
| RunCommand | Run shell command |
| CreateCommand | Save command |
| DeleteCommand | Delete saved command |
| UpdateCommandAttribute | Modify command |
| DescribeCommands | List commands |
| InvokeCommand | Execute saved command |
| DescribeInvocations | Command history |
| DescribeInvocationResult | Get command result |
| DescribeCommandInvocations | Command invocation details |
| InstallCloudAssistant | Install cloud assistant |
| DescribeCloudAssistantStatus | Check assistant status |
| DescribeCloudAssistantAttributes | Assistant attributes |

## Database

| API | Description |
|-----|-------------|
| DescribeDatabaseInstances | List databases |
| StartDatabaseInstance | Start DB |
| StopDatabaseInstance | Stop DB |
| RestartDatabaseInstance | Restart DB |
| ModifyDatabaseInstanceDescription | Modify DB description |
| ModifyDatabaseInstanceParameter | Modify DB parameter |
| DescribeDatabaseInstanceParameters | Get DB parameters |
| ResetDatabaseAccountPassword | Reset DB password |
| DescribeDatabaseErrorLogs | DB error logs |
| DescribeDatabaseSlowLogRecords | Slow query logs |
| DescribeDatabaseInstanceMetricData | DB metrics |
| AllocatePublicConnection | Allocate public endpoint |
| ReleasePublicConnection | Release public endpoint |

## Monitoring

| API | Description |
|-----|-------------|
| DescribeMonitorData | Instance metrics |
| ListInstancesTrafficPackages | Traffic usage |
| InstallCloudMonitorAgent | Install monitor agent |
| DescribeCloudMonitorAgentStatuses | Monitor agent status |
| DescribeSecurityAgentStatus | Security agent status |

## Tags

| API | Description |
|-----|-------------|
| TagResources | Add tags |
| UntagResources | Remove tags |
| ListTagResources | List tags |
