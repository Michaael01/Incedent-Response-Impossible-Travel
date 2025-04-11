# Incedent-Response-Impossible-Travel

# Explanation
Sometimes corporations have policies against working outside of designated geographic regions, account sharing (this should be standard), or use of non-corporate VPNs. The following scenario will be used to detect unusual logon behavior by creating an incident if a user's login patterns are too erratic. “Too erratic” can be defined as logging in from multiple geographic regions within a given time period.

Whenever a user logs into Azure or authenticates with their main Azure account, logs will be created in the “SigninLogs” table, which is being forwarded to the Log Analytics Workspace being used by Microsoft Sentinel, our SIEM. Within Sentinel, we will define an alert to trigger whenever a user logs into more than one location in a 7 day time period. Not all triggers will be true positives, but it will give us a chance to investigate.

# Detection and Analysis

Designed a Sentinel Scheduled Query Rule within Log Analytics that will discover when a user logs in to more than a certain number of locations within a given time period; for example, trigger if a user logs into 2 different geographic regions within a 7 day time period.
It was gathered that 2 accounts had been flagged for potential impossible travel.
1. 936158d7e14f6bd01ac6405dfbd7dadc73d4403d02dc63c4e3367686207935f7@lognpacific.com
2. 61f8b2dfc90aec741829201cdab353f99fcc3206d560235571bc8f81b0eb1b79@lognpacific.com

| Query used to locate events:                                                                                                                                        |
|--------------------------------------------------------------------------------------------------------------------------------------------------|
| let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look<br>SigninLogs<br>\| where TimeGenerated > ago(TimePeriodThreshold)<br>\| where UserPrincipalName == "61f8b2dfc90aec741829201cdab353f99fcc3206d560235571bc8f81b0eb1b79@lognpacific.com" or UserPrincipalName == "936158d7e14f6bd01ac6405dfbd7dadc73d4403d02dc63c4e3367686207935f7@lognpacific.com"<br>\| project TimeGenerated, UserPrincipalName = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)<br>\| order by Timestamp desc

![image](https://github.com/user-attachments/assets/20885bff-06d3-4495-9a7b-4a86c5bdee46)

# Containment, Eradication and Recovery
user 936158d7e14f6bd01ac6405dfbd7dadc73d4403d02dc63c4e3367686207935f7@lognpacific.com logged into Devils Lake and Golden within a 2 hours time period, which is not uncommon also user 61f8b2dfc90aec741829201cdab353f99fcc3206d560235571bc8f81b0eb1b79@lognpacific.com logged into tokyo and Saitama within 24 min time period which is not common.

Accepted that the users have intact expected behaviour. Therefore, the accounts were not disabled.
Lets say its an unexpected behaviour, I can immediately go to user account status in entra id and disable their account and after that, I will then reach out to the users manager for more investigation.

![user activity](https://github.com/user-attachments/assets/f83b3499-45f8-472c-8b1b-5321bda6dc66)

Further checked the activities of the user as shown in the above picture. It was therefore, determined that the alert was a TRUE Benign for both users since login times and locations were consistent with tzpical travel patterns

# Post-Incident Activities

Explored the option of implementing geofencing to prevent logins to specific geographic regians, such as restricting logins to within the same country or region.
