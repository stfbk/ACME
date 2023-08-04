from BaseRBAC import BaseRBAC
from adapters.CryptoAC.CryptoACRBAC import CryptoACRBAC
from locust import events
import json, requests , ssl, threading
import time
import asyncio
import websockets

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


    # Override: in this implementation, add variables for the socket
    def __init__(        
        self, 
        host, 
        logging,
        username,
        doInitialize
    ):
        super().__init__(
            host, 
            logging,
            username,
            doInitialize
        )
        self.url = self.host.replace("https://", "wss://") + '/v1/CryptoAC/resources/' + self.core + '/'
        self.wss = None
        self.asyncioLoopIsAvailable = False
        # If we are initializing, we assume that users' profiles
        # were not configured yet. Therefore, do not enable the
        # web socket, wait for the profiles to be ready
        if (self.doInitialize):
            self.socketIsEnabled = False
        # Otherwise, connect immediately the web socket
        else:
            self.socketIsEnabled = True


    # Start the socket
    async def start_websocket(self):
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        try: 
            async with websockets.connect(
                self.url, 
                ssl=ssl_context,
                extra_headers=self.copyCookiesAsHeaders(self.client)
            ) as websocket:
                self.wss = websocket
                self.logging.info("[start_websocket] Connection done, now wait for packets")
                while True:
                    packet = await self.wss.recv()
                    nowTime = str(time.time())
                    packet = json.loads(packet)
                    self.logging.warn(str(packet))
                    assert(packet["error"] == False)
                    if ("message" in packet):
                        originTime = packet["message"].split("_")[0]
                        events.request.fire(
                            request_type = "MessageReceived",
                            name = nowTime + "_" + originTime,
                            response_time = 0, 
                            response_length = 0,
                            exception=None,
                            context={}
                        )
                    else:
                        self.logging.info("[start_websocket] Received " 
                            + "message with no content: " 
                            + str(packet)
                        )
        except websockets.exceptions.ConnectionClosedOK:
            self.logging.info("WebSocket connection closed normally")
        except Exception as e:
            self.logging.error("WebSocket connection closed with error")
            self.logging.error(e.format_exc())


    # Wrapper for creating the event loop
    def start_websocket_wrapper(self):
        asyncio.run(self.start_websocket())


    # Override: in this implementation, also enable the socket
    def initialize(self, measure, alternativeInitializationData = None):
        self.logging.info("[initialize] Enable the web socket")
        result = super().initialize(measure, alternativeInitializationData)
        if (result):
            self.socketIsEnabled = True
        return result


    # Override: in this implementation, also close the socket
    #
    # Log out the adapter's client from the mechanism. It assumes that the
    # mechanism releases a session cookie that gets synchronized among all clients. 
    # - "measure": whether to make Locust measure the requests done during the logout
    def logout(self, measure):
        self.logging.info("[logout] Logging out")
        if (not self.wss is None):
            self.logging.info("[logout] Closing websocket")
            asyncio.ensure_future(self.wss.close(), loop=asyncio.get_event_loop())
            self.wss = None
        result = super().logout(measure)
        return result


    # Copy cookies in the socket
    def copyCookiesAsHeaders(self, request):
        self.logging.info("[copyCookiesAsHeaders] Copying cookies as headers")
        headers = {}
        cookies = request.cookies
        cookies_dict = requests.utils.dict_from_cookiejar(cookies)
        copiedCookies = []
        for cookie_name, cookie_value in cookies_dict.items():
            self.logging.info("[copyCookiesAsHeaders] - cookie name " + cookie_name + ", value " + cookie_value)
            copiedCookies.append(str(cookie_name) + "=" + str(cookie_value))
        headers["Cookie"] = ';'.join([copiedCookie for copiedCookie in copiedCookies])
        return headers


    # Override: in this implementation, "read" means "subscribe";
    # as such, do not logout after having sent the request, and
    # also connect the web socket
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
                    returnValue = True
                else:
                    self.logging.error("[readResource] Client already subscribed to topic " 
                        + resourceName 
                        + " but with role " 
                        + self.subscribedTopics[resourceName] 
                        + " and not with given role " 
                        + assumedRoleName
                    )
                    returnValue = False
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

                if (returnValue):
                    self.logging.info("[readResource] Starting the socket")
                    if (self.socketIsEnabled):
                        if (self.asyncioLoopIsAvailable):
                            self.logging.info("[readResource] socket is enabled, ensure_future")
                            asyncio.ensure_future(self.start_websocket(), loop=asyncio.get_event_loop())
                        else:
                            self.logging.info("[readResource] socket is enabled but no loop, launch thread")
                            thread = threading.Thread(target=self.start_websocket_wrapper)
                            thread.start()
                    else:
                        raise Exception("[readResource] socket is NOT enabled, this is error")


            # Below, there is code to use when MQTT messages are received not 
            # from the socket, but from the "_apiReadResource" function.
            # if (returnValue != "[]"):
            #     messages = json.loads(returnValue)
            #     for message in messages:
            #             messageValue = message["message"]
            #             events.request.fire(
            #                 request_type = "MessageReceived",
            #                 name = messageValue,
            #                 response_time = 0, 
            #                 response_length = 0,
            #                 exception=None,
            #                 context={}
            #             )

        return returnValue


    # Override: in this implementation, "write" means "publish";
    # as such, do not logout after having sent the request.
    # Also, append the timestamp before the content
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
            returnValue = self._apiWriteResource(
                clientToUse, 
                userToUse, 
                assumedRoleName, 
                resourceName, 
                str(time.time()) + "_" + resourceContent
            )
            
            # Do not logout as the user; otherwise, the user's core in CryptoAC
            # will be destroyed, hence disconnect from the broker
            
        return returnValue
    