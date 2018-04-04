# aws-cred-svc

Allows users to switch between multiple AWS roles by providing a local [Instance Metadata endpoint](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html).

## Running the application
OS specific scripts (Bash, AppleScript, and PowerShell) have been provided which apply the appropriate network settings and then launch the application.

## Add/Remove/Update AWS roles
The metadata service utilizes the the standard [AWS credential file](https://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html) to load role configurations (located in ~/.aws/credentials)

### Example

```
[account-creds]
aws_access_key_id = ACCESS_KEY_ID
aws_secret_access_key = SECRET_ACCESS_KEY

[profile1]
source_profile = account-creds
role_arn = arn:aws:iam::012345678901:role/role1

[profile2]
source_profile = account-creds
role_arn = arn:aws:iam::012345678901:role/role2
mfa_serial = arn:aws:iam::012345678901:mfa/{mfa_name}
```

## Switching Roles

### Method 1
Upon load, the application retrieves the profiles that are present in the local credentials file and displays them. Profiles can be switched by inputting the number associated with their load order.

### Method 2
Profiles can be activated and used with two HTTP requests  
1. GET http://169.254.169.254/latest/meta-data/iam/security-credentials/{profile}  
1. GET http://169.254.169.254/latest/meta-data/iam/security-credentials/{profile}/use  

## MFA Support
When mfa_serial is present, the service supports MFA code input by opening a dialog box in the user's desktop environment.

## Session Management
By default, a session is valid for one hour. For profiles configured with an mfa_serial, this means that users will need to reinput their MFA code after this time elapses.

Sessions are preemptively refreshed for another hour if utilized 20 minutes before expiration.

To persist an MFA session for extended periods of time, a CRON job (or scheduled task) can be configured to curl http://169.254.169.254/latest/meta-data/iam/security-credentials/{profile} every 20 minutes.  



