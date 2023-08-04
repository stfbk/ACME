import json, logging, base64, os, threading, requests, string, random, time


# To guarantee extensibility and preserve the generality of our methodology, 
# we implement the core logic of the simulator tool in this class, which is 
# independent of any AC mechanism. To implement an adapter, create a subclass
# of this class and implement all abstract methods (i.e., the methods whose 
# implementation here consists of a single line:
#    raise NotImplementedError("Implement this method in the subclass")
# 
# Please take a look at the adapters already implemented to get the intuition
# of how to create an adapter for another AC enforcement mechanism. Finally,
# override other eventual values (e.g., the name of the admin) and functions
# you need
class BaseRBAC(object):
    
    # The name of the admin user
    adminName = "admin"

    # Keep track of which users currently exists.
    # This list is filled at startup by the 'on_start' function
    usersU = []

    # Keep track of which roles currently exists.
    # This list is filled at startup by the 'on_start' function
    rolesR = []

    # Keep track of which resources currently exists.
    # This list is filled at startup by the 'on_start' function
    resourcesF = []

    # Keep track of which users are assigned to which roles.
    # The key is the role name, the value is the list of users.
    # This map is filled at startup by the 'on_start' function
    assignmentsUR = {}

    # Keep track of which roles are assigned to which resources.
    # The key is the role name, the value is a list of dictionaries where
    # each dictionary contains the resource name and the permission.
    # This map is filled at startup by the 'on_start' function
    permissionsPA = {}

    # Whether the AC enforcement mechanism was already initialized
    initialized = False

    # Whether the AC policy state was already acquired or not
    acquiredACPolicyState = False

    # Lock for managing the policy (e.g., U, R, P, UR, PA)
    policyLock = threading.Lock()
        
    # Lock for managing the 'on_start' function
    startLock = threading.Lock()


    def __init__(        
        self, 
        host, 
        logging,
        username,
        doInitialize
    ):
        self.host = host
        self.logging = logging
        self.username = username
        self.doInitialize = doInitialize
        self.client = None
        self.clientNotLogged = None
   

    # From the Locust documentation (https://docs.locust.io/en/stable/writing-a-locustfile.html?highlight=on_start#on-start-and-on-stop-methods):
    # "Users (and TaskSets) can declare an on_start method and/or on_stop method. A User will call its on_start method when it starts running, and its on_stop method when it stops running. For a TaskSet, the on_start method is called when a simulated user starts executing that TaskSet, and on_stop is called when the simulated user stops executing that TaskSet (when interrupt() is called, or the user is killed)."
    def on_start(self):
        # The "clientNotLogged" client is used to make requests
        # that will not be logged (and measured) by Locust
        self.clientNotLogged = self.cloneClientWithCookies()
        
        assert(self.login(measure = True))

        BaseRBAC.startLock.acquire()
        if (self.doInitialize and not BaseRBAC.initialized):
            BaseRBAC.initialized = True
            self.logging.info("Initializing the adapter")
            assert(self.initialize(measure = False))
        if (not BaseRBAC.acquiredACPolicyState):
            self.logging.info("Acquiring the policy state")
            BaseRBAC.acquiredACPolicyState = True
            BaseRBAC.usersU = self.getUsers(measure = False)
            BaseRBAC.rolesR = self.getRoles(measure = False)
            BaseRBAC.resourcesF = self.getResources(measure = False)
            BaseRBAC.assignmentsUR = self.getAssignments(measure = False)
            BaseRBAC.permissionsPA = self.getPermissions(measure = False)
            self.logging.info("Policy state acquired")
        BaseRBAC.startLock.release()

    # From the Locust documentation (https://docs.locust.io/en/stable/writing-a-locustfile.html?highlight=on_start#on-start-and-on-stop-methods):
    # "Users (and TaskSets) can declare an on_start method and/or on_stop method. A User will call its on_start method when it starts running, and its on_stop method when it stops running. For a TaskSet, the on_start method is called when a simulated user starts executing that TaskSet, and on_stop is called when the simulated user stops executing that TaskSet (when interrupt() is called, or the user is killed)."
    def on_stop(self):
        assert(self.logout(measure = True))

    # This method is invoked if the "doInitialize" option was specified.
    # - "measure": whether to make Locust measure the requests done during the initialization
    # - "alternativeInitializationData": alternative data to use for initializing the adapter
    def initialize(self, measure, alternativeInitializationData = None):
        raise NotImplementedError("Implement this method in the subclass")      

    # Log in the adapter's client toward the mechanism. It assumes that the
    # mechanism releases a session cookie that gets synchronized among all clients. 
    # - "measure": whether to make Locust measure the requests done during the login
    # - "alternativeUsername": alternative username to use when logging in (default is
    #   the adapter's username)
    def login(self, measure, alternativeUsername = None):
        clientToUse = self.client if (measure) else self.clientNotLogged
        usernameToUse = alternativeUsername if (alternativeUsername != None) else self.username
        returnValue = self._apiLogin(clientToUse, usernameToUse)
        if (measure):
            self.clientNotLogged.cookies = clientToUse.cookies
        else:
            self.client.cookies = clientToUse.cookies
        return returnValue

    # Log out the adapter's client from the mechanism. It assumes that the
    # mechanism releases a session cookie that gets synchronized among all clients. 
    # - "measure": whether to make Locust measure the requests done during the logout
    def logout(self, measure):
        clientToUse = self.client if (measure) else self.clientNotLogged
        returnValue = self._apiLogout(clientToUse)
        if (measure):
            self.clientNotLogged.cookies = clientToUse.cookies
        else:
            self.client.cookies = clientToUse.cookies
        return returnValue

    # Add a user to the access control policy and update the local policy (BaseRBAC.usersU) accordingly.
    # - "username": the name of the user to add
    # - "measure": whether to make Locust measure the requests done during the operation
    def addUser(self, username, measure):
        BaseRBAC.policyLock.acquire()
        if (not username in BaseRBAC.usersU):
            BaseRBAC.usersU.append(username)
            BaseRBAC.policyLock.release()
            clientToUse = self.client if (measure) else self.clientNotLogged
            returnValue = self._apiAddUser(clientToUse, username)
        else:
            BaseRBAC.policyLock.release()
            self.logging.warning("[addUser] User " + username + " already exists, ignoring operation")
            returnValue = True
        return returnValue

    # Add a role to the access control policy and update the local policy (BaseRBAC.rolesR) accordingly.
    # - "roleName": the name of the role to add
    # - "measure": whether to make Locust measure the requests done during the operation
    def addRole(self, roleName, measure):
        BaseRBAC.policyLock.acquire()
        if (not roleName in BaseRBAC.rolesR):
            BaseRBAC.rolesR.append(roleName)
            BaseRBAC.assignmentsUR[roleName] = []
            BaseRBAC.permissionsPA[roleName] = []
            BaseRBAC.policyLock.release()
            clientToUse = self.client if (measure) else self.clientNotLogged
            returnValue = self._apiAddRole(clientToUse, roleName)
        else:
            BaseRBAC.policyLock.release()
            self.logging.warning("[addRole] Role " + roleName + " already exists, ignoring operation")
            returnValue = True
        return returnValue

    # Add a resource to the access control policy and update the local policy (BaseRBAC.resourcesF) accordingly.
    # - "resourceName": the name of the resource to add
    # - "userToUse": the (name of the) user that is adding the resource
    # - "assumedRoleName": the (name of the) role that the user adding the resource assumes
    # - "resourceContent": the content of the resource
    # - "measure": whether to make Locust measure the requests done during the operation
    def addResource(self, resourceName, userToUse, assumedRoleName, resourceContent, measure):
        BaseRBAC.policyLock.acquire()
        if (not resourceName in BaseRBAC.resourcesF):
            BaseRBAC.resourcesF.append(resourceName)
            BaseRBAC.policyLock.release()

            # [NOT MEASURED] Logout from the admin account
            assert(self.logout(measure = False))

            # Login as the new user, add the resource and logout
            assert(self.login(measure = measure, alternativeUsername = userToUse))
            clientToUse = self.client if (measure) else self.clientNotLogged
            assert(self._apiAddResource(clientToUse, userToUse, resourceName, assumedRoleName, resourceContent))
            assert(self.logout(measure = measure))

            # [NOT MEASURED] Login back as the admin
            assert(self.login(measure = False))
            returnValue = resourceContent
        else:
            BaseRBAC.policyLock.release()
            self.logging.warning("[addResource] Resource " + resourceName + " already exists, ignoring operation")
            returnValue = True
        return returnValue

    # Delete a user from the access control policy and update the local policy accordingly.
    # - "username": the name of the user to delete
    # - "measure": whether to make Locust measure the requests done during the operation
    def deleteUser(self, username, measure):
        BaseRBAC.policyLock.acquire()
        if (username in BaseRBAC.usersU):
            BaseRBAC.usersU.remove(username)
            for roleName in BaseRBAC.assignmentsUR:
                if (username in BaseRBAC.assignmentsUR[roleName]):
                    BaseRBAC.assignmentsUR[roleName].remove(username)
            BaseRBAC.policyLock.release()
            clientToUse = self.client if (measure) else self.clientNotLogged
            returnValue = self._apiDeleteUser(clientToUse, username)
        else:
            BaseRBAC.policyLock.release()
            self.logging.warning("[deleteUser] User " + username + " does not exist, ignoring operation")
            returnValue = True
        return returnValue

    # Delete a role from the access control policy and update the local policy accordingly.
    # - "roleName": the name of the role to delete
    # - "measure": whether to make Locust measure the requests done during the operation
    def deleteRole(self, roleName, measure):
        BaseRBAC.policyLock.acquire()
        if (roleName in BaseRBAC.rolesR):
            BaseRBAC.rolesR.remove(roleName)
            del BaseRBAC.assignmentsUR[roleName]
            del BaseRBAC.permissionsPA[roleName]
            BaseRBAC.policyLock.release()
            clientToUse = self.client if (measure) else self.clientNotLogged
            returnValue = self._apiDeleteRole(clientToUse, roleName)
        else:
            BaseRBAC.policyLock.release()
            self.logging.warning("[deleteRole] Role " + roleName + " does not exist, ignoring operation")
            returnValue = True
        return returnValue

    # Delete a resource from the access control policy and update the local policy accordingly.
    # - "resourceName": the name of the resource to delete
    # - "measure": whether to make Locust measure the requests done during the operation
    def deleteResource(self, resourceName, measure):
        BaseRBAC.policyLock.acquire()
        if (resourceName in BaseRBAC.resourcesF):
            BaseRBAC.resourcesF.remove(resourceName)
            for roleName in BaseRBAC.permissionsPA:
                for currentPermission in BaseRBAC.permissionsPA[roleName]:
                    if (currentPermission["resource"] == resourceName):
                        BaseRBAC.permissionsPA[roleName].remove(currentPermission)
            BaseRBAC.policyLock.release()
            clientToUse = self.client if (measure) else self.clientNotLogged
            returnValue = self._apiDeleteResource(clientToUse, resourceName)
        else:
            BaseRBAC.policyLock.release()
            self.logging.warn("[deleteResource] Resource " + resourceName + " does not exist, ignoring operation")
            returnValue = True
        return returnValue
         
    # Assigns a user to a role in the access control policy and update the local policy accordingly.
    # - "username": the name of the user to assign
    # - "roleName": the name of the role to assign
    # - "measure": whether to make Locust measure the requests done during the operation
    def assignUserToRole(self, username, roleName, measure):
        BaseRBAC.policyLock.acquire()
        if (
            username not in BaseRBAC.usersU
            or
            roleName not in BaseRBAC.rolesR
        ):
            BaseRBAC.policyLock.release()
            self.logging.error("[assignUserToRole] User " 
                + username 
                + " or role " 
                + roleName 
                + " do not exist"
            )
            returnValue = False
        elif (username not in BaseRBAC.assignmentsUR[roleName]):
            BaseRBAC.assignmentsUR[roleName].append(username)
            BaseRBAC.policyLock.release()
            clientToUse = self.client if (measure) else self.clientNotLogged
            returnValue = self._apiAssignUserToRole(clientToUse, username, roleName)
        else:
            BaseRBAC.policyLock.release()
            self.logging.warning("[assignUserToRole] User " 
                + username 
                + " is already assigned to role "
                + roleName
                + ", ignoring operation"
            )
            returnValue = True
        return returnValue

    # Assigns a permission to a role in the access control policy and update the local policy accordingly.
    # - "roleName": the name of the role to assign
    # - "resourceName": the name of the resource to assign
    # - "permission": the permission to assign
    # - "measure": whether to make Locust measure the requests done during the operation
    def assignPermissionToRole(self, roleName, resourceName, permission, measure):
        BaseRBAC.policyLock.acquire()
        if (
            roleName not in BaseRBAC.rolesR
            or
            resourceName not in BaseRBAC.resourcesF
        ):
            BaseRBAC.policyLock.release()
            self.logging.error("[assignPermissionToRole] Role " 
                + roleName 
                + " or resource " 
                + resourceName 
                + " do not exist"
            )
            returnValue = False
        else:
            alreadyHasPermission = False
            for currentPermission in BaseRBAC.permissionsPA[roleName]:
                if (currentPermission["resource"] == resourceName and currentPermission["permission"] == permission):
                    alreadyHasPermission = True
            returnValue = True
            if (not alreadyHasPermission):
                BaseRBAC.permissionsPA[roleName].append(({
                    "resource":resourceName, "permission":permission
                }))
                BaseRBAC.policyLock.release()
                clientToUse = self.client if (measure) else self.clientNotLogged
                returnValue = self._apiAssignPermissionToRole(clientToUse, roleName, resourceName, permission)
            else:
                BaseRBAC.policyLock.release()
                self.logging.warning("[assignPermissionToRole] Role " 
                    + roleName 
                    + " already has permission over resource "
                    + resourceName
                    + ", ignoring operation"
                )
                returnValue = True
        return returnValue

    # Revoke a user from a role in the access control policy and update the local policy accordingly.
    # - "username": the name of the user to revoke
    # - "roleName": the name of the role to revoke
    # - "measure": whether to make Locust measure the requests done during the operation
    def revokeUserFromRole(self, username, roleName, measure):
        BaseRBAC.policyLock.acquire()
        if (
            username not in BaseRBAC.usersU
            or
            roleName not in BaseRBAC.rolesR
        ):
            BaseRBAC.policyLock.release()
            self.logging.error("[revokeUserFromRole] User " 
                + username 
                + " or role " 
                + roleName 
                + " do not exist"
            )
            returnValue = False
        elif (username in BaseRBAC.assignmentsUR[roleName]):
            BaseRBAC.assignmentsUR[roleName].remove(username)
            BaseRBAC.policyLock.release()
            clientToUse = self.client if (measure) else self.clientNotLogged
            returnValue = self._apiRevokeUserFromRole(clientToUse, username, roleName)
        else:
            BaseRBAC.policyLock.release()
            self.logging.warning("[revokeUserFromRole] User " 
                + username 
                + " is not assigned to role "
                + roleName
                + ", ignoring operation"
            )
            returnValue = True
        return returnValue

    # Revoke a permission from a role in the access control policy and update the local policy accordingly.
    # - "roleName": the name of the role to revoke
    # - "resourceName": the name of the resource to revoke
    # - "permission": the permission to revoke
    # - "measure": whether to make Locust measure the requests done during the operation
    def revokePermissionFromRole(self, roleName, resourceName, permission, measure):
        BaseRBAC.policyLock.acquire()
        if (
            roleName not in BaseRBAC.rolesR
            or
            resourceName not in BaseRBAC.resourcesF
        ):
            BaseRBAC.policyLock.release()
            self.logging.error("[revokePermissionFromRole] Role " 
                + roleName 
                + " or resource " 
                + resourceName 
                + " do not exist"
            )
            returnValue = False
        else:
            hasPermission = False
            for currentPermission in BaseRBAC.permissionsPA[roleName]:
                if (currentPermission["resource"] == resourceName):
                    BaseRBAC.permissionsPA[roleName].remove(currentPermission)
                    hasPermission = True
            BaseRBAC.policyLock.release()
            if (hasPermission):
                clientToUse = self.client if (measure) else self.clientNotLogged
                returnValue = self._apiRevokePermissionFromRole(clientToUse, roleName, resourceName, permission)
            else:
                self.logging.warning("[revokePermissionFromRole] Role " 
                    + roleName 
                    + " does not have permission over resource "
                    + resourceName
                    + ", ignoring operation"
                )
                returnValue = True
        return returnValue
    
    # Read (i.e., evaluate the request and download) a resource.
    # - "resourceName": the name of the resource to read
    # - "userToUse": the user reading the resource
    # - "assumedRoleName": the role that the user reading the resource assumes
    # - "measure": whether to make Locust measure the requests done during the operation
    def readResource(self, resourceName, userToUse, assumedRoleName, measure):
        BaseRBAC.policyLock.acquire()
        if (
            userToUse not in BaseRBAC.usersU
            or
            assumedRoleName not in BaseRBAC.rolesR
            or
            resourceName not in BaseRBAC.resourcesF
        ):
            BaseRBAC.policyLock.release()
            self.logging.error("[readResource] User " 
                + userToUse 
                + " or role " 
                + assumedRoleName 
                + " or resource " 
                + resourceName 
                + " do not exist"
            )
            returnValue = False
        else:
            BaseRBAC.policyLock.release()

            # [NOT MEASURED] Logout from the admin account
            assert(self.logout(measure = False))

            # Login as the new user, read the resource and logout
            assert(self.login(measure = measure, alternativeUsername = userToUse))
            clientToUse = self.client if (measure) else self.clientNotLogged
            returnValue = self._apiReadResource(clientToUse, userToUse, assumedRoleName, resourceName)
            assert(self.logout(measure = measure))

            # [NOT MEASURED] Login back as the admin
            assert(self.login(measure = False))
       
        return returnValue

    # Write (i.e., evaluate the request and upload) a resource.
    # - "resourceName": the name of the resource to write
    # - "userToUse": the user writing the resource
    # - "assumedRoleName": the role that the user writing the resource assumes
    # - "resourceContent": the new content of the resource
    # - "measure": whether to make Locust measure the requests done during the operation
    def writeResource(self, resourceName, userToUse, assumedRoleName, resourceContent, measure):
        BaseRBAC.policyLock.acquire()
        if (
            userToUse not in BaseRBAC.usersU
            or
            assumedRoleName not in BaseRBAC.rolesR
            or
            resourceName not in BaseRBAC.resourcesF
        ):
            BaseRBAC.policyLock.release()
            self.logging.error("[writeResource] User " 
                + userToUse 
                + " or role " 
                + assumedRoleName 
                + " or resource " 
                + resourceName 
                + " do not exist"
            )
            returnValue = False
        else:
            BaseRBAC.policyLock.release()

            # [NOT MEASURED] Logout from the admin account
            assert(self.logout(measure = False))

            # Login as the new user, write the resource and logout
            assert(self.login(measure = measure, alternativeUsername = userToUse))
            clientToUse = self.client if (measure) else self.clientNotLogged
            returnValue = self._apiWriteResource(clientToUse, userToUse, assumedRoleName, resourceName, resourceContent)
            assert(self.logout(measure = measure))

            # [NOT MEASURED] Login back as the admin
            assert(self.login(measure = False))
        return returnValue


    # Get the currently existing usernames as a set of strings.
    def getUsers(self, measure): 
        clientToUse = self.client if (measure) else self.clientNotLogged
        return self._apiGetUsers(clientToUse)


    # Get the currently existing role's names as a set of strings.
    def getRoles(self, measure): 
        clientToUse = self.client if (measure) else self.clientNotLogged
        return self._apiGetRoles(clientToUse)


    # Get the currently existing resource's names as a set of strings.
    def getResources(self, measure): 
        clientToUse = self.client if (measure) else self.clientNotLogged
        return self._apiGetResources(clientToUse)


    # Get the currently existing user-role assignments 
    # as a dictionary (key is role name, value is list 
    # of assigned users).
    def getAssignments(self, measure): 
        clientToUse = self.client if (measure) else self.clientNotLogged
        return self._apiGetAssignments(clientToUse)


    # Get the currently existing role-resource assignments 
    # as a dictionary (key is role name, value is list 
    # of assigned resources).
    def getPermissions(self, measure): 
        clientToUse = self.client if (measure) else self.clientNotLogged
        return self._apiGetPermissions(clientToUse)


    # Return a random user assigned to the given role name
    def getRandomUserFromRole(self, roleName):
        userToReturn = BaseRBAC.adminName
        while (userToReturn == BaseRBAC.adminName):
            userToReturn = random.choice(BaseRBAC.assignmentsUR[roleName])
            if (
                userToReturn == BaseRBAC.adminName
                and
                len(BaseRBAC.assignmentsUR[roleName]) == 1
            ):
                logging.warn("There is only user admin for role " + roleName)
                break
        return userToReturn


    # Return a session (python-requests) with the same
    # cookies as self.client. However, requests made 
    # with the returned session will not be logged 
    # by Locust
    def cloneClientWithCookies(self):
        sessionCookies = self.client.cookies
        clonedSession = requests.Session()
        clonedSession.cookies = sessionCookies
        clonedSession.verify = False
        return clonedSession

    # Set the client
    def setClient(self, client):
        self.client = client


    # Return a random alphabetic string of the given size
    def idGenerator(self, size=6, chars=string.ascii_letters + string.digits):
        return ''.join(random.choice(chars) for _ in range(size))


    # Log in the username using the clientToUse toward the mechanism.
    def _apiLogin(self, clientToUse, username):
        raise NotImplementedError("Implement this method in the subclass")

    # Log out the clientToUse from the mechanism.
    def _apiLogout(self, clientToUse):
        raise NotImplementedError("Implement this method in the subclass")

    # Add a user to the access control policy.
    def _apiAddUser(self, clientToUse, username):
        raise NotImplementedError("Implement this method in the subclass")

    # Add a role to the access control policy.
    def _apiAddRole(self, clientToUse, roleName):
        raise NotImplementedError("Implement this method in the subclass")

    # Add a resource to the access control policy.
    def _apiAddResource(self, clientToUse, userToUse, resourceName, assumedRoleName, resourceContent):
        raise NotImplementedError("Implement this method in the subclass")

    # Delete a user from the access control policy.
    def _apiDeleteUser(self, clientToUse, username):
        raise NotImplementedError("Implement this method in the subclass")

    # Delete a role from the access control policy.
    def _apiDeleteRole(self, clientToUse, roleName):
        raise NotImplementedError("Implement this method in the subclass")

    # Delete a resource from the access control policy.
    def _apiDeleteResource(self, clientToUse, resourceName):
        raise NotImplementedError("Implement this method in the subclass")

    # Assign a user to a role in the access control policy.
    def _apiAssignUserToRole(self, clientToUse, username, roleName):
       raise NotImplementedError("Implement this method in the subclass")

    # Assign a permission to a role in the access control policy.
    def _apiAssignPermissionToRole(self, clientToUse, roleName, resourceName, permission):
        raise NotImplementedError("Implement this method in the subclass")

    # Revoke a user from a role in the access control policy.
    def _apiRevokeUserFromRole(self, clientToUse, username, roleName):
       raise NotImplementedError("Implement this method in the subclass")

    # Revoke a permission from a role in the access control policy.
    def _apiRevokePermissionFromRole(self, clientToUse, roleName, resourceName, permission):
        raise NotImplementedError("Implement this method in the subclass")

    # Read a resource.
    def _apiReadResource(self, clientToUse, username, assumedRoleName, resourceName): 
        raise NotImplementedError("Implement this method in the subclass")

    # Write a resource.
    def _apiWriteResource(self, clientToUse, userToUse, assumedRoleName, resourceName, resourceContent): 
        raise NotImplementedError("Implement this method in the subclass")

    # Get the currently existing user names as a set of strings.
    def _apiGetUsers(self, clientToUse):
        raise NotImplementedError("Implement this method in the subclass")

    # Get the currently existing role names as a set of strings.
    def _apiGetRoles(self, clientToUse):
        raise NotImplementedError("Implement this method in the subclass")

    # Get the currently existing resource names as a set of strings.
    def _apiGetResources(self, clientToUse):
        raise NotImplementedError("Implement this method in the subclass")

    # Get the currently existing user-role assignments 
    # as a dictionary (key is role name, value is list 
    # of assigned users).
    def _apiGetAssignments(self, clientToUse):
        raise NotImplementedError("Implement this method in the subclass")

    # Get the currently existing role-resource assignments 
    # as a dictionary (key is role name, value is list 
    # of assigned resources).
    def _apiGetPermissions(self, clientToUse):
        raise NotImplementedError("Implement this method in the subclass")
