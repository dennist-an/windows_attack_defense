# windows_attack_defense
### AS-REP Roasting Attack
The AS-REProasting attack is similar to the Kerberoasting attack; we can obtain crackable hashes for user accounts that have the property Do not require Kerberos preauthentication enabled. The success of this attack depends on the strength of the user account password that we will crack.

When preauthentication is enabled, a user who needs access to a resource begins the Kerberos authentication process by sending an Authentication Server Request (AS-REQ) message to the domain controller (DC). The timestamp on that message is encrypted with the hash of the user’s password. If the DC can decrypt that timestamp using its own record of the user’s password hash, it will send back an Authentication Server Response (AS-REP) message that contains a Ticket Granting Ticket (TGT) issued by the Key Distribution Center (KDC), which is used for future access requests by the user.

However in the case of AS-REP roasting, if preauthentication is disabled, an attacker could request authentication data for any user and the DC would return an AS-REP message. Since part of that message is encrypted using the user’s password, the attacker can then attempt to brute-force the user’s password offline.

To obtain crackable hashes,Rubeus will be used. If we do not specify a name, Rubeus will extract hashes for each user that has *Kerberos preauthentication not required*:
```.\Rubeus.exe asreproast /outfile:asrep.txt```


### AS-REP Roasting Detection
When we executed Rubeus, an Event with ID 4768 (A Kerberos authentication ticket (TGT) was requested) was generated, signaling that a Kerberos Authentication ticket was generated:

#### Roasted hashes
The caveat is that AD generates this event for every user that authenticates with Kerberos to any device; therefore, the presence of this event is very abundant. However, it is possible to know where the user authenticated from, which we can then use to correlate known good logins against potential malicious hash extractions. It may be hard to inspect specific IP addresses, especially if a user moves around office locations. However, it is possible to scrutinize the particular VLAN and alert on anything outside it.

### AS-REP Roasting Prevention
As mentioned before, the success of this attack depends on the strength of the password of users with *Do not require Kerberos preauthentication* configured.

First and foremost, we should only use this property if needed; a good practice is to review accounts quarterly to ensure that we have not assigned this property. Because this property is often found with some regular user accounts, they tend to have easier-to-crack passwords than service accounts with SPNs (those from Kerberoast). Therefore, for users requiring this configured, we should assign a separate password policy, which requires at least 20 characters to thwart cracking attempts.

### AS-REProasting Honeypot
However, suppose the honeypot user is the only account with Kerberos Pre-Authentication not required. In that case, there might be better detection methods, as it would be very obvious for advanced threat actors that it is a honeypot user, resulting in them avoiding interactions with it. (I did previously hear from an organization that needed one of these accounts (application related) that the 'security through obscurity' behind having only one of these accounts may save them, as attackers will avoid going after it thinking it is a honeypot user. While it may be true in some instances, we should not let a glimpse of hope dictate the security state of the environment.)