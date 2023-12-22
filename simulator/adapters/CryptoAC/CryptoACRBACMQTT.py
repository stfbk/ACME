from BaseRBAC import BaseRBAC
from adapters.CryptoAC.CryptoACRBAC import CryptoACRBAC
from locust import events
import json, base64, os

# Adapter for CryptoAC (MQTT)
class CryptoACRBACMQTT(CryptoACRBAC):

    core = "RBAC_MQTT"

    # Profile for CryptoAC RBAC_MQTT without DYNSEC
    adminProfile = {
        "type":"eu.fbk.st.cryptoac.core.CoreParametersRBAC",
        "user":{
            "name":"admin",
            "status":"INCOMPLETE",
            "isAdmin":True,
            "token":"admin"
        },
        "coreType":"RBAC_MQTT",
        "cryptoType":"SODIUM",
        "versionNumber":1,
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
            "type":"eu.fbk.st.cryptoac.dm.mqtt.DMServiceMQTTParameters",
            "username":"admin",
            "password":"password",
            "port":1883,
            "url":"10.1.0.8",
            "tls":False,
            "dmType":"MQTT"
        },
        "rmServiceParameters":None,
        "acServiceParameters":None
    }

    # The map of topics to which the (user
    # logged in by using the HTTP client 
    # of this) adapter is subscribed to.
    # Key is name of topic, value is the name
    # of the role used to subscribe to the topic
    subscribedTopics = {}

    alreadyInvokedWriteResource = False


    # Override: in this implementation, "read" means "subscribe";
    # as such, do not logout after having sent the request.
    #
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

            # If we are already subscribed to this topic
            if (resourceName in self.subscribedTopics):
                if (self.subscribedTopics[resourceName] == assumedRoleName):
                    self.logging.info("[readResource] Already subscribed to topic " + resourceName)
                else:
                    self.logging.error("[readResource] Client already subscribed to topic " 
                        + resourceName 
                        + " but with role " 
                        + self.subscribedTopics[resourceName] 
                        + " and not with given role " 
                        + assumedRoleName
                    )
                    return False
            else:
                self.logging.info("[readResource] Was not subscribed to topic " + resourceName)

                # [NOT MEASURED] Logout from the admin account
                assert(self.logout(measure = False))

                # Login as the new user, read the resource and logout
                assert(self.login(measure = measure, alternativeUsername = userToUse))
                
                self.subscribedTopics[resourceName] = assumedRoleName
                
                # Do not logout as the user; otherwise, the user's core in CryptoAC
                # will be destroyed, hence unsubscribed from all topics


            clientToUse = self.client if (measure) else self.clientNotLogged
            returnValue = self._apiReadResource(clientToUse, userToUse, assumedRoleName, resourceName)

            if (returnValue != "[]"):
                messages = json.loads(returnValue)
                self.logging.info("[readResource] Received number of " + str(len(messages)) + " messages")
                for message in messages:
                    if ("message" in message):
                        events.request.fire(
                            request_type = "MessageReceived",
                            name = message["message"] + "_" + base64.b64encode(os.urandom(10))[:10].decode('utf-8'),
                            response_time = 0, 
                            response_length = 0,
                            exception=None,
                            context={}
                        )
                    else:
                        self.logging.info("[readResource] Received " 
                            + "message with no content: " 
                            + str(message)
                        )
            else:
                self.logging.info("[readResource] Received number of 0 messages")
                            
        return returnValue


    # Override: in this implementation, "write" means "publish";
    # as such, do not logout after having sent the request.
    #
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

            # If we are not already connected to the broker
            if (not self.alreadyInvokedWriteResource):
                self.logging.info("[writeResource] First publish")

                self.alreadyInvokedWriteResource = True

                # [NOT MEASURED] Logout from the admin account
                assert(self.logout(measure = False))

                # Login as the new user, write the resource and logout
                assert(self.login(measure = measure, alternativeUsername = userToUse))
            else:
                self.logging.info("[writeResource] Subsequent publish")

            clientToUse = self.client if (measure) else self.clientNotLogged
            returnValue = self._apiWriteResource(clientToUse, userToUse, assumedRoleName, resourceName, resourceContent)
            
            # Do not logout as the user; otherwise, the user's core in CryptoAC
            # will be destroyed, hence disconnect from the broker
            
        return returnValue
    