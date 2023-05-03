entity- either a user or a hostname
login - either: test@mail.com or just: test
role API_ACCESS_MANAGEMENT_ADMIN is added again even if already exists- Okta
limit - if empty, returns by default 200 results for list_users, and 20 for providers


Add group - Takes a name for a new group and optionally a description, and creates the new group. If it already exists, the existing group is returned.
A table containing the group information is added.

Assign role - Takes user ids as a parameter, and optionally runs on a scope of user logins and tries to add the given role types to the user.
A table containing the assigned roles' information is added.

Ussign role - Takes user ids as a parameter, and optionally runs on a scope of user logins and tries to remove the given role types or id from the user.

Disable user - Takes either user ids or user logins (through a parameter or entities). Suspends the user by default. Deactivates the user if "Is Deactivate" is TRUE. Optionally sends an email to the admin after deactivation.

Enable user - Takes either user ids or user logins (through a parameter or entities). Unsuspends the user by default. Activates the user if "Is Activate" is TRUE. Optionally sends an email to the admin after activation.

Get group - Takes a list of group ids or a list of group names and returns their data.
A table containing the group information is added.

Get user - Takes either user ids or user logins (through a parameter or entities). Returns the users' information.
A table containing the user information is added.

List providers - lists providers by a query, type and a limit (all are optional).
A table containing the provider information is added.

List roles - Takes user ids as a parameter, and optionally runs on a scope of user logins and lists the given roles for the user.
A table containing the roles' information is added.

List user groups - Takes either user ids or user logins (through a parameter or entities) and returns the groups that the users are members of.
A table containing the users' groups information is added.

List users - lists users by a query, filter, search and a limit (all are optional).
A table containing the user information is added.

Reset password - Takes either user ids or user logins (through a parameter or entities) and resets the users' passwords. If "Send Email" is TRUE, the user receives a link for the password reset. Otherwise, the link is returned for every user.

Set password - Takes either user ids or user logins (through a parameter or entities) and sets a new password for the users. Optionally add 10 random characters to every user's password to make it unique.
The passwords are returned.