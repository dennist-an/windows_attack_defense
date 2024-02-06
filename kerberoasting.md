# windows_attack_defense
### Kerberoast Attack
Kerberoasting is a post-exploitation attack that attempts to exploit this behavior by obtaining a ticket and performing offline password cracking to open the ticket.

To understand Kerberoasting, there is an item we need to define that plays a huge part during this attack technique. Service Principal Names (SPN) is used to uniquely identify a Windows Service. Kerberos authentication requires that with each service logon account there must be a SPN associated. This allows a client to request a service ticket without having the actual account name through Kerberos authentication.

The SPN is not automatically created when you create the user in Active Directory, you HAVE to go and create the SPN. You can see below how to do this:
```setspn -a thanos/WINDOMAIN.local:60111 WINDOMAIN\thanos```

When the Kerberoast attack is executed, an adversary can use Domain credentials captured on any user to request Kerberos TGS tickets for accounts that are associated with the SPN records in Active Directory (AD). The TGS tickets are signed with the targeted user or services NTLM hash. This can then be cracked offline to retrieve the clear text password. By default, the tools to automate this process will retrieve the TGS ticket in the encrypted RC4 algorithm. This is where we can start to build our baseline in detecting this attack. The adversary can then crack that hash with hashcat 13100 and a wordlist to find the password for that/those accounts.

Extracts out the tickets for every user that has an SPN registered.
```.\Rubeus.exe kerberoast /outfile:spn.txt```

### Differences between Kerberoasting and AS-REP Roasting
AS-REP Roasting has the same IDEA of Kerberoasting but is different in the fact that an account needs “Do not require Kerberos pre-authentication”. For Kerberos v5 you have to manually go in and disable Kerberos pre-auth. The only reason I can think of someone to actually want to do this is for backwards compatibility with Kerberos v4 libraries, which by default a password was not required for authentication. Another difference between the two, is AS-REP requests a Kerberos Authentication Ticket (TGT) not a service authentication ticket (TGS). The hashes you get between AS-REP and Kerberoasting are different. To crack the hash (if using hashcat you will need to change from 13100 to 18200 this is because Kerberoast requests TGS and AS-REP request TGT)

### Kerberoast Detection
When a TGS is requested, an event log with ID 4769 (Kerberos Ticket Granting Service (TGS) ticket request) is generated. However, AD also generates the same event ID whenever a user attempts to connect to a service, which means that the volume of this event is gigantic, and relying on it alone is virtually impossible to use as a detection method. If we happen to be in an environment where all applications support AES and only AES tickets are generated, then it would be an excellent indicator to alert on event ID 4769. If the ticket options is set for RC4, that is, if RC4 tickets are generated in the AD environment (which is not the default configuration), then we should alert and follow up on it.

### Kerberoast Prevention
The success of this attack depends on the strength of the service account's password. While we should limit the number of accounts with SPNs and disable those no longer used/needed, we must ensure they have strong passwords. For any service that supports it, the password should be 100+ random characters (127 being the maximum allowed in AD), which ensures that cracking the password is practically impossible.

There is also what is known as Group Managed Service Accounts (GMSA), which is a particular type of a service account that Active Directory automatically manages; this is a perfect solution because these accounts are bound to a specific server, and no user can use them anywhere else. Additionally, Active Directory automatically rotates the password of these accounts to a random 127 characters value. There is a caveat: not all applications support these accounts, as they work mainly with Microsoft services (such as IIS and SQL) and a few other apps that have made integration possible. However, we should utilize them everywhere possible and start enforcing their use for new services that support them to out phase current accounts eventually.

When in doubt, do not assign SPNs to accounts that do not need them. Ensure regular clean-up of SPNs set to no longer valid services/servers.

### Kerberoast Honeypot
A honeypot user is a perfect detection option to configure in an AD environment; this must be a user with no real use/need in the environment, so no service tickets are generated regularly. In this case, any attempt to generate a service ticket for this account is likely malicious and worth inspecting. There are a few things to ensure when using this account:

  - The account must be a relatively old user, ideally one that has become bogus (advanced threat actors will not request tickets for new accounts because they likely have strong passwords and the possibility of being a honeypot user).
  - The password should not have been changed recently. A good target is 2+ years, ideally five or more. But the password must be strong enough that the threat agents cannot crack it.
  - The account must have some privileges assigned to it; otherwise, obtaining a ticket for it won't be of interest (assuming that an advanced adversary obtains tickets only for interesting accounts/higher likelihood of cracking, e.g., due to an old password).
  - The account must have an SPN registered, which appears legit. IIS and SQL accounts are good options because they are prevalent.
An added benefit to honeypot users is that any activity with this account, whether successful or failed logon attempts, is suspicious and should be alerted.