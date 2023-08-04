from BaseRBAC import BaseRBAC
import threading, requests, string, random, json, time

# Adapter for CryptoAC
class CryptoACRBAC(BaseRBAC):

    # Profile for CryptoAC RBAC_CLOUD without OPA
    adminProfile = {
        "type":"eu.fbk.st.cryptoac.core.CoreParametersRBAC",
        "user":{
            "name":"admin",
            "status":"INCOMPLETE",
            "isAdmin":True,
            "token":"admin"
        },
        "coreType":"RBAC_AT_REST",
        "cryptoType":"JAVA",
        "versionNumber":1,
        "rmServiceParameters":{
            "type":"eu.fbk.st.cryptoac.rm.cryptoac.RMServiceCryptoACParameters",
            "port":8443,
            "username":"admin",
            "password":"password",
            "url":"10.1.0.4",
            "rmType":"CRYPTOAC"
        },
        "mmServiceParameters":{
            "type":"eu.fbk.st.cryptoac.mm.redis.MMServiceRedisParameters",
            "username":"admin",
            "password":"password",
            "port":6379,
            "url":"10.1.0.7",
            "token":"admin",
            "mmType":"RBAC_REDIS"
        },
        "dmServiceParameters":{
            "type":"eu.fbk.st.cryptoac.dm.cryptoac.DMServiceCryptoACParameters",
            "port":8443,
            "username":"admin",
            "password":"password",
            "url":"10.1.0.5",
            "dmType":"CRYPTOAC"
        },
        "acServiceParameters":None
    }


    def initialize(self, measure, alternativeInitializationData = None):
        clientToUse = self.client if (measure) else self.clientNotLogged
        profileToUse = alternativeInitializationData if (alternativeInitializationData != None) else self.adminProfile
        if (alternativeInitializationData != None):
            self.initialized = True
        return self._addProfile(clientToUse, profileToUse)


    def addUser(self, username, measure):
        CryptoACRBAC.policyLock.acquire()
        if (not username in CryptoACRBAC.usersU):
            CryptoACRBAC.usersU.append(username)
            CryptoACRBAC.policyLock.release()
            clientToUse = self.client if (measure) else self.clientNotLogged
            userParameters = json.loads(self._apiAddUser(clientToUse, username))
            assert(self.logout(measure = measure))
            assert(self.login(alternativeUsername = username, measure = measure))
            assert(self.initialize(measure = False, alternativeInitializationData = userParameters))
            assert(self.logout(measure = measure))
            assert(self.login(measure = measure))
            return True
        else:
            CryptoACRBAC.policyLock.release()
            self.logging.warn("[addUser] User " + username + " already exists")
            returnValue = False
        return returnValue


    def _apiLogin(self, clientToUse, username):
        returnValue = False
        with clientToUse.post(
            self.host + '/login/', 
            data = {'username': username}
        ) as response:
            returnValue = (response.text == "\"CODE_000_SUCCESS\"")
        return returnValue


    def _apiLogout(self, clientToUse):
        returnValue = False
        with clientToUse.delete(
            self.host + '/logout/'
        ) as response:
            returnValue = (response.text == "\"CODE_000_SUCCESS\"")
        return returnValue


    def _apiAddUser(self, clientToUse, username):
        with clientToUse.post(
            self.host + '/v1/CryptoAC/users/RBAC_AT_REST/',
            data={'Username':username}
        ) as response:
            assert(response.status_code == 200)
            returnValue = response.text
        return returnValue


    def _apiAddRole(self, clientToUse, roleName):
        with clientToUse.post(
            self.host + '/v1/CryptoAC/roles/RBAC_AT_REST/',
            data={'Role_Name':roleName}
        ) as response:
            returnValue = (response.text == "\"CODE_000_SUCCESS\"")
        return returnValue


    def _apiAddResource(self, clientToUse, userToUse, resourceName, assumedRoleName, resourceContent):
        resources = {resourceName: resourceContent}
        with clientToUse.post(
                self.host + '/v1/CryptoAC/resources/RBAC_AT_REST/',
                data = {'Access_Control_Enforcement': 'COMBINED'},
                files = resources
            ) as response:
                returnValue = (response.text == "\"CODE_000_SUCCESS\"")
        return returnValue

        
    def _apiDeleteUser(self, clientToUse, username):
        returnValue = False
        with clientToUse.delete(
            self.host + '/v1/CryptoAC/users/RBAC_AT_REST/' + username
        ) as response:
            returnValue = (response.text == "\"CODE_000_SUCCESS\"")
        return returnValue


    def _apiDeleteRole(self, clientToUse, roleName):
        returnValue = False
        with clientToUse.delete(
            self.host + '/v1/CryptoAC/roles/RBAC_AT_REST/' + roleName
        ) as response:
            returnValue = (response.text == "\"CODE_000_SUCCESS\"")
        return returnValue


    def _apiDeleteResource(self, clientToUse, resourceName):
        returnValue = False
        with clientToUse.delete(
            self.host + '/v1/CryptoAC/resources/RBAC_AT_REST/' + resourceName
        ) as response:
            returnValue = (response.text == "\"CODE_000_SUCCESS\"")
        return returnValue


    def _apiAssignUserToRole(self, clientToUse, username, roleName):
        with clientToUse.post(
            self.host + '/v1/CryptoAC/assignments/RBAC_AT_REST/', 
            data={'Username':username, 'Role_Name':roleName},
        ) as response:
            returnValue = (
                response.text == "\"CODE_000_SUCCESS\"" 
                or 
                response.text == "\"CODE_010_ROLETUPLE_ALREADY_EXISTS\""
            )
        return returnValue


    def _apiAssignPermissionToRole(self, clientToUse, roleName, resourceName, permission):
        returnValue = False
        if (permission.upper() == "WRITE"):
            permission = "READWRITE"
        with clientToUse.post(
            self.host + '/v1/CryptoAC/permissions/RBAC_AT_REST/', 
            data={'Role_Name':roleName, 'Resource_Name':resourceName, 'Permission':permission.upper()}
        ) as response:
            returnValue = (response.text == "\"CODE_000_SUCCESS\"")
        return returnValue


    def _apiRevokeUserFromRole(self, clientToUse, username, roleName):
        returnValue = False
        with clientToUse.delete(
            self.host + '/v1/CryptoAC/assignments/RBAC_AT_REST/' + username + '/' + roleName
        ) as response:
            returnValue = (response.text == "\"CODE_000_SUCCESS\"")
        return returnValue


    def _apiRevokePermissionFromRole(self, clientToUse, roleName, resourceName, permission):
        returnValue = False
        if (permission == "READ"):
            permission = "READWRITE" 
        with clientToUse.delete(
            self.host + '/v1/CryptoAC/permissions/RBAC_AT_REST/' + roleName + '/' + resourceName + '/' + permission
        ) as response:
            returnValue = (response.text == "\"CODE_000_SUCCESS\"")
        return returnValue

   
    def _apiReadResource(self, clientToUse, username, assumedRoleName, resourceName): 
        with clientToUse.get(
            self.host + '/v1/CryptoAC/resources/RBAC_AT_REST/' + resourceName, 
            stream = True
        ) as response:
            fileContentChunks = bytearray(b'')
            for chunk in response.iter_content(chunk_size=1024):
                fileContentChunks.extend(chunk)
            resourceContent = fileContentChunks.decode('utf-8')
        return resourceContent


    def _apiWriteResource(self, clientToUse, userToUse, assumedRoleName, resourceName, resourceContent): 
        resources = {resourceName: resourceContent}
        with clientToUse.patch(
                self.host + '/v1/CryptoAC/resources/RBAC_AT_REST/',
                data = {'Access_Control_Enforcement': 'COMBINED'},
                files = resources
            ) as response:
                returnValue = (response.text == "\"CODE_000_SUCCESS\"")
        return returnValue


    def _apiGetUsers(self, clientToUse):
        with clientToUse.get(
            self.host + '/v1/CryptoAC/users/RBAC_AT_REST/'
        ) as response:
            returnValue = []
            users = response.json()
            for user in users:
                returnValue.append(user['name'])
        return returnValue


    def _apiGetRoles(self, clientToUse):
        with clientToUse.get(
            self.host + '/v1/CryptoAC/roles/RBAC_AT_REST/'
        ) as response:
            returnValue = []
            roles = response.json()
            for role in roles:
                returnValue.append(role['name'])
        return returnValue


    def _apiGetResources(self, clientToUse):
        with clientToUse.get(
            self.host + '/v1/CryptoAC/resources/RBAC_AT_REST/'
        ) as response:
            returnValue = []
            resources = response.json()
            for resource in resources:
                returnValue.append(resource['name'])
        return returnValue


    def _apiGetAssignments(self, clientToUse):
        returnValue = {}
        with clientToUse.get(
            self.host + '/v1/CryptoAC/assignments/RBAC_AT_REST/'
        ) as response:
            roleTuples = response.json()
            for roleTuple in roleTuples:
                username = roleTuple['username']
                roleName = roleTuple['roleName']
                returnValue.setdefault(roleName, []).append(username)
        return returnValue


    def _apiGetPermissions(self, clientToUse):
        returnValue = {}
        with clientToUse.get(
            self.host + '/v1/CryptoAC/permissions/RBAC_AT_REST/'
        ) as response:
            permissionTuples = response.json()
            for permissionTuple in permissionTuples:
                roleName = permissionTuple['roleName']
                resourceName = permissionTuple['resourceName']
                permission = permissionTuple['permission']
                if (permission == "READWRITE"):
                    returnValue.setdefault(roleName, []).append({
                        "resource":resourceName, "permission":"READ"
                    })
                    returnValue[roleName].append({
                        "resource":resourceName, "permission":"WRITE"
                    })
                else:
                    returnValue.setdefault(roleName, []).append({
                        "resource":resourceName, "permission":permission
                    })
        return returnValue




    def _addProfile(self, clientToUse, profileToUse):
        returnValue = False
        with clientToUse.post(
            self.host + '/v1/profile/RBAC_AT_REST/',
            json = profileToUse
        ) as response:
            returnValue = (response.text == "\"CODE_000_SUCCESS\"")
        return returnValue
