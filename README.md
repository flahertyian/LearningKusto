LearnKusto
May 2025 Workshop
https://github.com/KustoKing/LearnKusto

  Practice materiel maintainers:
  Gianni Castaldi,
  Bert-Jan Pals

----
Ian Flaherty - [linkedin](https://www.linkedin.com/in/flahertyian/)


### Exercise 1

# Questions

## ✅ 1. What is the schema of the dataset?

Basic KQL datatable initalization statment for a CSV dataset

## ✅ 2. How many records are in the dataset?
select the datatable then `count` the number of rows
```
Excersise1
| count
```

100 records


## ✅ 3. What are the distinct ActionTypes present in the dataset?

Use `distinct` operator to only return unique rows
```
Excersise1
| distinct ActionType
```
<details>
  <summary>Query Output</summary>
    
    ActionType
    LdapSearch
    AntivirusScanCompleted
    AntivirusDetection
    ScreenshotTaken
    ExploitGuardNonMicrosoftSignedBlocked
    DriverLoad
    ExploitGuardChildProcessAudited
    TamperingAttempt
    DnsQueryResponse
    TvmAxonTelemetryEvent
    ScheduledTaskCreated
    PnpDeviceAllowed
    AppControlCodeIntegritySigningInformation
    PowerShellCommand
    OtherAlertRelatedActivity
    AntivirusReport
    ClrUnbackedModuleLoaded
    NtAllocateVirtualMemoryApiCall
    CreateRemoteThreadApiCall
    AuditPolicyModification
    ContainedUserLogonBlocked
    ShellLinkCreateFileEvent
    ScheduledTaskDeleted
    OpenProcessApiCall
    DpapiAccessed
    NamedPipeEvent
    BrowserLaunchedToOpenUrl
    UserAccountModified
    ReadProcessMemoryApiCall
    ServiceInstalled
    SmartScreenAppWarning
    NtProtectVirtualMemoryApiCall
    AntivirusDetectionActionType
    ScheduledTaskUpdated
    AntivirusScanCancelled
    ContainedUserRemoteDesktopSessionStopped
    ProcessCreatedUsingWmiQuery
    PnpDeviceConnected
    ContainedUserRemoteDesktopSessionDisconnected
    UserAccountAddedToLocalGroup
</details>
  
## ✅ 4. How many events from Device-007 are present in the dataset?

Using the `where` operator we can return only the rows with a specific device name.
Then we `count` the rows that are returned.
```
Excersise1
| where DeviceName == "Device-007"
| count
```

9 Events from Device-007

## ✅ 5. How many PowerShellCommand actions were initiated from C:\Windows\System32?

Using the `where` operator again with the `and` keyword we can check multiple colums for matches.
```
Excersise1
| where FileName == "powershell.exe" and InitiatingProcessFolderPath == @"C:\Windows\System32"
```

Three actions matched this query
<details>
  <summary>Query Output</summary>

  | Timestamp | DeviceId | DeviceName | ActionType | FileName | AccountSid | InitatingProcessSHA1 | InitiatingProcessFolderPath |
  |-----------------------------|---------|------------|------------------------------|----------------|----------------------|------------------------------------------|----------------------|
  | 2025-05-01 05:15:25.2144290 |	759931	|	Device-005 | ProcessCreatedUsingWmiQuery	|	powershell.exe |	S-1-5-21-5616355490 |	a962ece76d6feabefb5393f33f6bd157febd8281 |	C:\Windows\System32 |
  | 2025-05-01 05:25:50.2144290 |	412878	|	Device-018 |	UserAccountAddedToLocalGroup |	powershell.exe |	S-1-5-21-7357154875 |	bc7a8b8673a7ef6bf9f908f01d5c67b0dc86acaf |	C:\Windows\System32 |
  | 2025-05-01 07:04:30.2144290	| 513778	|	Device-014 |	PnpDeviceConnected | powershell.exe |	S-1-5-21-3148255165 |	1abfbb67cfbedd62a8a24bf98607cc6b2cae1c21 |	C:\Windows\System32 |
</details>

### Exercise 2

# Questions

## ✅ 1. List the successful login count per application.

Again we use `where` to match successfull logins,
Then we use the `summarize` operator to agrigate and sort our output.
In this case I Summarized count by AppDisplayName.
however in heindsight this data would look better sorted as AppDisplayName by count
```
Excersise2
| where ResultDescription == "Success"
| summarize count() by AppDisplayName
```

<details>
    <summary>Query Output</summary>
        
  | AppDisplayName | count_ |
  |----------------|--------|
  | Microsoft Azure Workflow | 6 |
  | Microsoft Cloud App Security | 7 |
  | Skype for Business Online |10 |
  | Dataverse | 4 |
  | Yammer | 9 |
  | Microsoft Office 365 Portal | 3 |
  | Windows Azure Active Directory | 6 | 
  | Office 365 SharePoint Online | 3 |
  | Microsoft Graph | 7 |
  | Azure ESTS Service | 5 |
  | Office 365 Exchange Online | 7 |
  | Azure API Management | 10 |
</details>
## ✅ 2. Create a piechart with the distribution of sign-in events per application.

Use the `render` operator to use selected data in a specified graph/visualization.
The `sort` operator can be used to sort data by another column.
Idealy this will be set in the `summarize` operator
```
Excersise2
| where ResultType == "0"
| summarize count() by AppDisplayName
| sort by count_
| render piechart with(title="Successfull logins by App")
```

<img width="1070" height="668" alt="EX2_Q2" src="https://github.com/user-attachments/assets/5aa0c0ac-b555-4e73-95b3-c58bfa9abaf7" />


## ✅ 3. Create a barchart/columnchart with the number of sign-in activities to the Graph API per user.

Use the `title` variable of render to set a title
```
Excersise2
| where AppDisplayName == "Microsoft Graph"
| summarize count() by UserPrincipalName
| sort by count_
| render columnchart with(title="Login activity to MSGraph by User")
```

<img width="1506" height="676" alt="EX2_Q3" src="https://github.com/user-attachments/assets/3fb15124-8093-419f-9c8b-c81cb645d091" />


## ✅ 4. Creaet a timechart with the number of failed sign-in activities per day.

the `bin` operator when used with summarize can be used to standardize scattered data into increments sothat it fits more nicley on a graph. 
Use `xtitle` and `ytitle` to set titles for axis
```
Excersise2
| where ResultType != 0
| summarize FailedSignIn = count() by bin(TimeGenerated, 1d)
| render timechart with(title="Failed sign in attempts by day", ytitle="# of Attempts", xtitle="Time")
```

<img width="1757" height="663" alt="EX2_Q4" src="https://github.com/user-attachments/assets/0194f9ec-da5c-40ae-a5af-d7eb536ec6b7" />

