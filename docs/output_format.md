# Output CSV File Documentation

## Packages1_{ReviewID}.csv
This file contains information about groups and their logical groupings.

| Column | Source | Description |
|--------|--------|-------------|
| ReviewID | Parameter | The ReviewID provided when running the script |
| GroupID | AD Group | The ObjectGUID of the group from Active Directory |
| ReviewPackageID | Generated | Deterministic GUID generated from group base name, ReviewID, and group ObjectGUID<br>Format: 8-4-4-4-12 hexadecimal digits (e.g., "12345678-1234-1234-1234-123456789012") |
| GroupName | AD Group | For logical groups: base name without suffix (e.g., "FinanceApp" from "FinanceApp-ro")<br>For regular groups: full group name |
| PrimaryOwnerEmail | AD User | Extracted from group's info attribute using regex to find name, then searched in AD<br>Patterns: "Primary: First Last", "P: First Last", "Primary Owner: First Last" |
| SecondaryOwnerEmail | AD User | Extracted from group's info attribute using regex to find name, then searched in AD<br>Patterns: "Secondary: First Last", "S: First Last", "Secondary Owner: First Last" |
| OUPath | groups.json | The OU path where the group is located |
| Tag | groups.json | The category specified in the groups.json configuration |
| Description | AD Group | The group's description from Active Directory |
| LogicalGrouping | groups.json | Boolean indicating if this is part of a logical group (true/false) |
| LogicalAccess | groups.json | Access level based on suffix (e.g., "Read-Only" for "-ro", "Change" for "-ch") |

## PackageMembers1_{ReviewID}.csv
This file contains information about group members and their access levels.

| Column | Source | Description |
|--------|--------|-------------|
| FirstName | AD User | User's GivenName attribute |
| LastName | AD User | User's Surname attribute |
| Email | AD User | User's mail attribute |
| UserID | AD User | User's ObjectGUID |
| Username | AD User | Concatenation of GivenName and Surname |
| Department | AD User | User's department attribute |
| JobTitle | AD User | User's title attribute |
| ManagerName | AD User | Concatenation of manager's GivenName and Surname |
| ManagerEmail | AD User | Manager's mail attribute |
| ReviewPackageID | Inherited | Same as the group's ReviewPackageID (GUID) to link members to their group |
| DerivedGroup | AD Group | The actual group name the user is a member of (including suffix) |
| LogicalAccess | Inherited | Same as the group's LogicalAccess value |

## Packages2_{ReviewID}.csv
This file contains information about user accounts in the specified OUs.

| Column | Source | Description |
|--------|--------|-------------|
| ReviewID | Parameter | The ReviewID provided when running the script |
| GroupID | AD User | The ObjectGUID of the user account |
| GroupName | AD User | User's DisplayName attribute |
| OUPath | privilege.json | The OU path where the user is located |
| ReviewPackageID | Generated | Deterministic GUID generated from user's SamAccountName, ReviewID, and user ObjectGUID<br>Format: 8-4-4-4-12 hexadecimal digits (e.g., "12345678-1234-1234-1234-123456789012") |

## PrivilegeGroups_{ReviewID}.csv
This file contains information about groups that users are members of.

| Column | Source | Description |
|--------|--------|-------------|
| GroupName | AD Group | The name of the group |
| GroupID | AD Group | The ObjectGUID of the group |
| ReviewPackageID | Inherited | Same as the user's ReviewPackageID (GUID) to link groups to their user |
| Description | AD Group | The group's description from Active Directory |

## Relationships Between Files

1. **Group to Member Relationship**:
   - Packages1.ReviewPackageID → PackageMembers1.ReviewPackageID
   - Links group members to their respective groups using GUIDs
   - Example: All members of "FinanceApp-ro" share the same ReviewPackageID GUID as their group

2. **User to Privilege Group Relationship**:
   - Packages2.ReviewPackageID → PrivilegeGroups.ReviewPackageID
   - Links privilege groups to their respective users using GUIDs
   - Example: All groups that "John Smith" is a member of share his ReviewPackageID GUID

## ReviewPackageID Generation

ReviewPackageIDs are deterministic GUIDs generated using the following process:

1. **For Groups**:
   ```
   Input = "{BaseName}|{ReviewID}|{GroupObjectGUID}"
   Example: "FinanceApp|REVIEW-2024-001|{GUID1}"
   ```

2. **For Users**:
   ```
   Input = "{SamAccountName}|{ReviewID}|{UserObjectGUID}"
   Example: "john.smith|REVIEW-2024-001|{GUID2}"
   ```

3. **Generation Process**:
   1. Create SHA256 hash of the input string
   2. Convert hash to a proper GUID
   3. Result is a valid GUID in format: 8-4-4-4-12 hexadecimal digits

This ensures:
- Each ReviewPackageID is a valid GUID
- Same input always produces the same GUID
- GUIDs are consistent between runs
- Proper linking between related records

## Owner Extraction Process

1. **Regex Pattern Matching**:
   The script looks for owner names in the group's info attribute using these patterns:
   ```
   Primary: First Last
   P: First Last
   Primary Owner: First Last
   Secondary: First Last
   S: First Last
   Secondary Owner: First Last
   ```

2. **AD User Lookup**:
   For each matched name:
   1. Extract first and last name
   2. Search AD for users with matching last name
   3. Filter results for matching first name
   4. Get email address from the matching user

Example:
```
Group Info:
Primary: John Smith
Secondary: Jane Doe

Process:
1. Extract "John Smith"
   - Search AD for surname "Smith"
   - Filter for given name "John"
   - Get email from matching user
2. Extract "Jane Doe"
   - Search AD for surname "Doe"
   - Filter for given name "Jane"
   - Get email from matching user
```

## Example Data Flow

1. **Logical Group Processing**:
   ```
   Group: FinanceApp-ro
   ├─ ReviewPackageID: 12345678-1234-1234-1234-123456789012
   ├─ GroupName: FinanceApp
   ├─ LogicalAccess: Read-Only
   └─ Members:
      ├─ John Smith (ReviewPackageID: 12345678-1234-1234-1234-123456789012)
      └─ Sarah Jones (ReviewPackageID: 12345678-1234-1234-1234-123456789012)
   ```

2. **User Privilege Processing**:
   ```
   User: John Smith
   ├─ ReviewPackageID: 87654321-4321-4321-4321-210987654321
   └─ Groups:
      ├─ Finance Department (ReviewPackageID: 87654321-4321-4321-4321-210987654321)
      └─ Finance Approvers (ReviewPackageID: 87654321-4321-4321-4321-210987654321)
   ``` 