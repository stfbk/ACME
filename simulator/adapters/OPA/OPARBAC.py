from BaseRBAC import BaseRBAC
import json, logging, time

# Adapter for OPA (no file storage)
class OPARBAC(BaseRBAC):

    # The file containing initialization 
    # code for the OPA RBAC policy
    initializationFileRego = "./simulator/adapters/OPA/rbac.rego" 


    def initialize(self, measure, alternativeInitializationData = None):
        clientToUse = self.client if (measure) else self.clientNotLogged
        self.initialized = True
        return self._putPolicy(clientToUse)


    def _apiLogin(self, clientToUse, username):
        return True


    def _apiLogout(self, clientToUse):
        return True


    def _apiAddUser(self, clientToUse, username):
        return True
 

    def _apiAddRole(self, clientToUse, roleName):
        return True   
        

    def _apiAddResource(self, clientToUse, userToUse, resourceName, assumedRoleName, resourceContent):
        return True   


    def _apiDeleteUser(self, clientToUse, username):
        return self._updateOPADocumentFromPolicy(clientToUse)


    def _apiDeleteRole(self, clientToUse, roleName):
        return self._updateOPADocumentFromPolicy(clientToUse)
    

    def _apiDeleteResource(self, clientToUse, resourceName):
        return self._updateOPADocumentFromPolicy(clientToUse)


    def _apiAssignUserToRole(self, clientToUse, username, roleName):
        return self._updateOPADocumentFromPolicy(clientToUse)

    
    def _apiAssignPermissionToRole(self, clientToUse, roleName, resourceName, permission):
        return self._updateOPADocumentFromPolicy(clientToUse)
            

    def _apiRevokeUserFromRole(self, clientToUse, username, roleName):
        return self._updateOPADocumentFromPolicy(clientToUse)


    def _apiRevokePermissionFromRole(self, clientToUse, roleName, resourceName, permission):
        return self._updateOPADocumentFromPolicy(clientToUse)


    def _apiReadResource(self, clientToUse, username, assumedRoleName, resourceName):
        with clientToUse.post(
            self.host + '/v1/data/rbac/allow',
            data = json.dumps({'input':{'username':username, 'resource':resourceName, 'permission':'READ'}}),
        ) as response:
            assert(response.status_code == 200)
            evalResult = json.loads(response.text)["result"]
            returnValue = (evalResult == True)
        return returnValue


    def _apiWriteResource(self, clientToUse, userToUse, assumedRoleName, resourceName, resourceContent): 
        with clientToUse.post(
            self.host + '/v1/data/rbac/allow',
            data = json.dumps({'input':{'username':userToUse, 'resource':resourceName, 'permission':'WRITE'}}),
        ) as response:
            assert(response.status_code == 200)
            evalResult = json.loads(response.text)["result"]
            returnValue = (evalResult == True)
        return returnValue


    def _apiGetUsers(self, clientToUse):
        with clientToUse.get(
            self.host + '/v1/data/rbac',
        ) as response:
            returnValue = set()
            opaAssignmentsUR = (response.json()["result"])["ur"]
            for username in opaAssignmentsUR:
                returnValue.add(username)
        return list(returnValue)


    def _apiGetRoles(self, clientToUse):
        with clientToUse.get(
            self.host + '/v1/data/rbac',
        ) as response:
            returnValue = set()
            opaAssignmentsUR = (response.json()["result"])["ur"]
            for username in opaAssignmentsUR:
                returnValue.update(set(opaAssignmentsUR[username]))
        return list(returnValue)


    def _apiGetResources(self, clientToUse):
        with clientToUse.get(
            self.host + '/v1/data/rbac',
        ) as response:
            returnValue = set()
            opaPermissionsPA = (response.json()["result"])["pa"]
            for roleName in opaPermissionsPA:
                for currentPermission in opaPermissionsPA[roleName]:
                    returnValue.add(currentPermission["resource"])
        return list(returnValue)


    def _apiGetAssignments(self, clientToUse):
        with clientToUse.get(
            self.host + '/v1/data/rbac',
        ) as response:
            returnValue = {}
            opaAssignmentsUR = (response.json()["result"])["ur"]
            for username in opaAssignmentsUR:
                roleNames = opaAssignmentsUR[username]
                for roleName in roleNames:
                    if (roleName not in returnValue):
                        returnValue[roleName] = []
                    if (username not in returnValue[roleName]):
                        returnValue[roleName].append(username) 
        return returnValue


    def _apiGetPermissions(self, clientToUse):
        with clientToUse.get(
            self.host + '/v1/data/rbac',
        ) as response:
            returnValue = {}
            opaPermissionsPA = (response.json()["result"])["pa"]
            for roleName in opaPermissionsPA:
                returnValue[roleName] = []
                for currentPermission in opaPermissionsPA[roleName]:
                    returnValue[roleName].append({
                        "resource":currentPermission["resource"], "permission":currentPermission["permission"]
                    })
        return returnValue




    def _putPolicy(self, clientToUse):
        returnValue = False
        with open(self.initializationFileRego) as fileRego:
            regoCode = fileRego.read()
            with clientToUse.put(
                self.host + '/v1/policies/rbac',
                data = regoCode,
            ) as responsePutPolicy:
                returnValue = (responsePutPolicy.status_code == 200)
                if (returnValue):
                    with clientToUse.put(
                        self.host + '/v1/data/rbac',
                        json = json.loads("{\"ur\":{}, \"pa\":{}}"),
                    ) as responsePutData:
                        returnValue = (responsePutData.status_code == 204)
        return returnValue


    def _updateOPADocumentFromPolicy(self, clientToUse):
        assignmentsURByUser = {}
        for roleName in OPARBAC.assignmentsUR:
            for username in OPARBAC.assignmentsUR[roleName]:
                if (username not in assignmentsURByUser):
                    assignmentsURByUser[username] = []
                assignmentsURByUser[username].append(roleName)

        newPolicy = ("{ "
            + "\"randomID\":\"" 
            + self.idGenerator(size=10)      
            + "\", \"ur\":" 
            + json.dumps(assignmentsURByUser) 
            + ", \"pa\":"
            + json.dumps(OPARBAC.permissionsPA) 
            + "}")
        
        logging.debug("Updating OPA document from policy")
        logging.debug(newPolicy)
        
        headers = {'Content-type': 'application/json'}
        with clientToUse.put(
            self.host + '/v1/data/rbac',
            data = newPolicy,
            headers = headers
        ) as response:
            returnValue = response.status_code == 204
        return returnValue

