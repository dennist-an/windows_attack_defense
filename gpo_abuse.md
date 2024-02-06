# windows_attack_defense
### Group Policy Object Permissions/GPO Files Abuse
When we create a new GPO, only Domain admins (and similar privileged roles) can modify it. However, within environments, we will encounter different delegations that allow less privileged accounts to perform edits on the GPOs; this is where the problem lies. Many organizations have GPOs that can modify 'Authenticated Users' or 'Domain Users', which entails that any compromised user will allow the attacker to alter these GPOs. Modifications can include additions of start-up scripts or a scheduled task to execute a file, for example. This access will allow an adversary to compromise all computer objects in the OUs that the vulnerable GPOs are linked to.

Similarly, administrators perform software installation via GPOs or configure start-up scripts located on network shares. If the network share is misconfigured, an adversary may be able to replace the file to be executed by the system with a malicious one. The GPO may have no misconfigurations in these scenarios, just misconfigured NTFS permissions on the files deployed.

### Group Policy Object Permissions/GPO Files Detection
It is straightforward to detect when a GPO is modified. If Directory Service Changes auditing is enabled, then the event ID 5136 (A directory service object was modified.) will be generated.

### Group Policy Object Permissions/GPO Files Prevention
One way to prevent this attack is to lock down the GPO permissions to be modified by a particular group of users only or by a specific account, as this will significantly limit the ability of who can edit the GPO or change its permissions (as opposed to everybody in Domain admins, which in some organizations can easily be more than 50). Similarly, never deploy files stored in network locations so that many users can modify the share permissions.

We should also review the permissions of GPOs actively and regularly, with the option of automating a task that runs hourly and alerts if any deviations from the expected permissions are detected.