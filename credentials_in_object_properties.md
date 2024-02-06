# windows_attack_defense
### Credentials in Object Properties
Objects in Active Directory have a plethora of different properties; for example, a user object can contain properties that contain information such as:

- Is the account active
- When does the account expire
- When was the last password change
- What is the name of the account
- Office location for the employee and phone number

When administrators create accounts, they fill in those properties. A common practice in the past was to add the user's (or service account's) password in the Description or Info properties, thinking that administrative rights in AD are needed to view these properties. However, every domain user can read most properties of an object (including Description and Info).

A simple PowerShell script can query the entire domain by looking for specific search terms/strings in the Description or Info fields:
```
Function SearchUserClearTextInformation
{
    Param (
        [Parameter(Mandatory=$true)]
        [Array] $Terms,

        [Parameter(Mandatory=$false)]
        [String] $Domain
    )

    if ([string]::IsNullOrEmpty($Domain)) {
        $dc = (Get-ADDomain).RIDMaster
    } else {
        $dc = (Get-ADDomain $Domain).RIDMaster
    }

    $list = @()

    foreach ($t in $Terms)
    {
        $list += "(`$_.Description -like `"*$t*`")"
        $list += "(`$_.Info -like `"*$t*`")"
    }

    Get-ADUser -Filter * -Server $dc -Properties Enabled,Description,Info,PasswordNeverExpires,PasswordLastSet |
        Where { Invoke-Expression ($list -join ' -OR ') } | 
        Select SamAccountName,Enabled,Description,Info,PasswordNeverExpires,PasswordLastSet | 
        fl
}
```
### Credentials in Shares Detection
Baselining users' behavior is the best technique for detecting abuse of exposed credentials in properties of objects. Although this can be tricky for regular user accounts, triggering an alert for administrators/service accounts whose behavior can be understood and baselined is easier. Automated tools that monitor user behavior have shown increased success in detecting abnormal logons. In the example above, assuming that the provided credentials are up to date, we would expect events with event ID 4624/4625 (failed and successful logon) and 4768 (Kerberos TGT requested).

Unfortunately, the event ID 4738 generated when a user object is modified does not show the specific property that was altered, nor does it provide the new values of properties. Therefore, we cannot use this event to detect if administrators add credentials to the properties of objects.
**Tips:**
Another detection technique is discovering the one-to-many connections, for example, when Invoke-ShareFinder scans every domain device to obtain a list of its network shares. It would be abnormal for a workstation to connect to 100s or even 1000s of other devices simultaneously.

### Credentials in Shares Prevention
We have many options to prevent this attack/misconfiguration:

- Perform continuous assessments to detect the problem of storing credentials in properties of objects.
- Educate employees with high privileges to avoid storing credentials in properties of objects.
- Automate as much as possible of the user creation process to ensure that administrators don't handle the accounts manually, reducing the risk of introducing hardcoded credentials in user objects.

### Credentials in Shares honeypot
Storing credentials in properties of objects is an excellent honeypot technique for not-very-mature environments. If struggling with basic cyber hygiene, then it is more likely expected to have such issues (storing credentials in properties of objects) in an AD environment. For setting up a honeypot user, we need to ensure the followings:

- The password/credential is configured in the Description field, as it's the easiest to pick up by any adversary.
- The provided password is fake/incorrect.
- The account is enabled and has recent login attempts.
- While we can use a regular user or a service account, service accounts are more likely to have this exposed as administrators tend to create them manually. In contrast, automated HR systems often make employee accounts (and the employees have likely changed the password already).
- The account has the last password configured 2+ years ago (makes it more believable that the password will likely work).