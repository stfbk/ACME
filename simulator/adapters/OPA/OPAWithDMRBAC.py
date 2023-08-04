from adapters.OPA.OPARBAC import OPARBAC
import json

# Adapter for OPA (with file storage)
class OPAWithDMRBAC(OPARBAC):

    # The parameters with which configure the DM
    dmConfigureParameters = {"type":"eu.fbk.st.cryptoac.ac.opa.ACServiceRBACOPAParameters","port":8181,"url":"10.1.0.6","acType":"RBAC_OPA"}

    # The IP and port of the DM
    hostDM = "https://127.0.0.1:8445"


    def initialize(self, measure, alternativeInitializationData = None):
        clientToUse = self.client if (measure) else self.clientNotLogged
        returnValue = super().initialize(measure)
        if (returnValue):
            with clientToUse.post(
                self.hostDM + '/v1/dm/RBAC_AT_REST/', 
                data = json.dumps(self.dmConfigureParameters),
                headers = {'Content-type': 'application/json'}
            ) as response:
                returnValue = (response.text == "\"CODE_000_SUCCESS\"")
        return returnValue


    def _apiDeleteResource(self, clientToUse, resourceName):
        with clientToUse.delete(
            self.hostDM + '/v1/dm/resources/RBAC_AT_REST/' + resourceName + '?Username=' + self.adminName
        ) as response:
            returnValue = (response.text == "\"CODE_000_SUCCESS\"")
        return returnValue
  

    def _apiAddResource(self, clientToUse, userToUse, resourceName, assumedRoleName, resourceContent):
        resources = {resourceName: resourceContent}
        with clientToUse.post(
                self.hostDM + '/v1/dm/resources/RBAC_AT_REST/',
                files = resources
            ) as response:
                returnValue = (response.text == "\"CODE_000_SUCCESS\"")
        if (returnValue):
            with clientToUse.put(
                self.hostDM + '/v1/dm/resources/RBAC_AT_REST/' + resourceName + '?Username=' + userToUse, 
                data = {'Resource_Name': resourceName}
            ) as response:
                returnValue = (response.text == "\"CODE_000_SUCCESS\"")      
        return returnValue
   

    def _apiReadResource(self, clientToUse, username, assumedRoleName, resourceName):
        with clientToUse.get(
            self.hostDM + '/v1/dm/resources/RBAC_AT_REST/' + resourceName + '?Username=' + username, 
            stream = True
        ) as response:
            if (response.status_code == 200):
                fileContentChunks = bytearray(b'')
                for chunk in response.iter_content(chunk_size=1024):
                    fileContentChunks.extend(chunk)
                resourceContent = fileContentChunks.decode('utf-8')
            else:
                resourceContent = False
        return resourceContent


    def _apiWriteResource(self, clientToUse, userToUse, assumedRoleName, resourceName, resourceContent): 
        resources = {resourceName: resourceContent}
        with clientToUse.post(
                self.hostDM + '/v1/dm/resources/RBAC_AT_REST/',
                files = resources
            ) as response:
                returnValue = (response.text == "\"CODE_000_SUCCESS\"")
        if (returnValue):
            with clientToUse.put(
                self.hostDM + '/v1/dm/resources/RBAC_AT_REST/' + resourceName + '?Username=' + userToUse, 
                data = {'Resource_Name': resourceName}
            ) as response:
                returnValue = (response.text == "\"CODE_000_SUCCESS\"")      
        return returnValue
