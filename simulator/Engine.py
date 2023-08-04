# at the beginning of the script
import gevent.monkey
gevent.monkey.patch_all()

from locust import TaskSet, constant, events, HttpUser, task
from locust.user.task import DefaultTaskSet
from locust.exception import StopUser
from locust.env import Environment
from locust.runners import Runner, MasterRunner, WorkerRunner
from functools import wraps
from io import UnsupportedOperation
from plistlib import InvalidFileException
from BaseRBAC import BaseRBAC
from adapters.CryptoAC.CryptoACRBAC import CryptoACRBAC
from adapters.CryptoAC.CryptoACRBACMQTT import CryptoACRBACMQTT
from adapters.OPA.OPARBAC import OPARBAC
from adapters.OPA.OPAWithDMRBAC import OPAWithDMRBAC
from adapters.XACML.XACMLRBAC import XACMLRBAC
from adapters.XACML.XACMLWithDMRBAC import XACMLWithDMRBAC
import logging, base64, json, os, urllib3, threading, sys, random, traceback, time, string, datetime
from gevent.lock import Semaphore
import os, os.path

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global variables
host = None                             # Host toward which send the requests (e.g., usually the URL)
adapterToUse = None                     # Type of adapter to use (e.g., CryptoAC, OPA, OPAWithDM, XACML, XACMLWithDM)
workflowsAndPaths = {}                  # Key is the name of the workflow, value is list of paths
shuffle = False                         # Whether to choose a random execution in workflows at each task
reserveUsers = False                    # Whether to reserve users for executing operations
ignoreAddUser = False                   # Whether to ignore add user operations
ignoreAddRole = False                   # Whether to ignore add role operations
ignoreAddResource = False               # Whether to ignore add resource operations
ignoreDeleteUser = False                # Whether to ignore delete user operations
ignoreDeleteRole = False                # Whether to ignore delete role operations
ignoreDeleteResource = False            # Whether to ignore delete resource operations
ignoreAssignUser = False                # Whether to ignore assign user (to role) operations
ignoreAssignPermission = False          # Whether to ignore assign role (to resource) operations
ignoreRevokeUser = False                # Whether to ignore revoke user (from role) operations
ignoreRevokePermission = False          # Whether to ignore revoke role (from resource) operations
ignoreReadResource = False              # Whether to ignore read resource operations
ignoreWriteResource = False             # Whether to ignore write resource operations
ignorePersistentAssignRevokePermission = False # Whether to ignore assign and revoke permissions regarding persistent resources
uniqueUserNames = False                 # Whether usernames are unique to the workflow instance
uniqueRoleNames = False                 # Whether role names are unique to the workflow instance
uniqueTransientResourceNames = False    # Whether transient resource names are unique to the workflow instance
doInitialize = None                     # Whether the adapter needs to be initialized
repeatWorkflows = None                  # How many times to repeat each workflow before terminating the test
workerID = None                         # The ID of this worker (used for, e.g., logs and names)
iterations = None                       # Run at most this number of task iterations and terminate once they have finished
locustEnv = None                        # The Locust environment
userSemaphores = {}                     # dictionary of semaphores; the key is the user name, the value the corresponding semaphore
policySemaphore = None                  # semaphore to wait for the master to grant permission to modify the policy
usersReserved = []                      # The list of users currently busy doing an operation. Whenever a user is selected # to execute an operation through a role, that user # cannot be selected for another operation until the # first one is completed. This approach concurs in # simulating a realistic environment in which each # user carries out a single activity at a given time
policyReserved = False                  # Whether the policy is currently reserved for a worker
masterUsersLock = threading.Lock()      # Lock allowing the master to sync requests (of reserving and releasing users) from workers
masterPolicyLock = threading.Lock()     # Lock allowing the master to sync requests (of reserving and releasing the policy) from workers
workersPolicyRequests = []              # List of worker IDs that requested to reserve the policy (i.e., queue of workers to answer to)
workersUserRequests = {}                # Key is username, value is list of worker IDs that requested that username (i.e., queue of workers to answer to)
reservePolicy = False                   # Whether to lock the policy (it makes modifications to the policy sequential, not concurrent)
syncPolicyAcrossWorkers = False         # Whether to synchronize the AC policy state across workers (this requires the "reservePolicy" flag)
acksOfPolicyUpdateToReceive = None      # If the policy is synchronized, this is the number of acks to receive from workers to ensure that every worker synced successfully
numberOfWorkers = 0                     # The total number of workers


# For each workflow, the index (in the list) of the last path that was executed
latestPathExecutedIndexPerWorkflow = {}

# The index of the last workflow that was selected for execution
latestWorkflowExecutedIndex = 0

# For each workflow, the number of paths
numberOfPathsPerWorkflow = {}

# For each workflow, how many times each path was executed
numberOfRepetitionsPerPathByWorkflow = {}    


# Utility method to create an instance of the chosen adapter
def getInstanceOfAdapter(
    username
):
    global adapterToUse, doInitialize, host
    if (adapterToUse == "CryptoAC"):
        return CryptoACRBAC(
            host = host, 
            logging = logging,
            username = CryptoACRBAC.adminName,
            doInitialize = doInitialize
        )
    elif (adapterToUse == "CryptoACMQTT"):
        return CryptoACRBACMQTT(
            host = host, 
            logging = logging,
            username = CryptoACRBACMQTT.adminName,
            doInitialize = doInitialize
        )
    elif (adapterToUse == "OPA"):
        return OPARBAC(
            host = host, 
            logging = logging,
            username = username,
            doInitialize = doInitialize
        )
    elif (adapterToUse == "OPAWithDM"):
        return OPAWithDMRBAC(
            host = host, 
            logging = logging,
            username = username,
            doInitialize = doInitialize
        )
    elif (adapterToUse == "XACML"):
        return XACMLRBAC(
            host = host, 
            logging = logging,
            username = XACMLRBAC.adminName,
            doInitialize = doInitialize
        )
    elif (adapterToUse == "XACMLWithDM"):
        return XACMLWithDMRBAC(
            host = host, 
            logging = logging,
            username = XACMLWithDMRBAC.adminName,
            doInitialize = doInitialize
        )
    else:
        message = "Adapter " + adapterToUse + " not supported"
        logging.error(message)
        raise UnsupportedOperation(message)


# Utility method to return a random base64-encoded string of the given size
def getRandomString(sizeInBytes):
    return base64.b64encode(os.urandom(sizeInBytes))[:sizeInBytes].decode('utf-8')


# Fired when the worker receives a message of type "user_was_reserved"
# Do not insert wait, sleeps, locks or semaphores acquires in listeners;
# Instead, spawn a dedicated thread    
def masterReservedUserListener(environment, msg, **kwargs):
    global workerID, userSemaphores
    recepientWorkerID = msg.data["workerID"] 
    usernameReserved = msg.data["username"]
    if (workerID == recepientWorkerID):
        userSemaphores[usernameReserved].release()
        logging.debug("Worker received message from master, reserved user " 
            + usernameReserved
            + ", released semaphore"
        )
    else:
        logging.debug("Worker received message from master that user " 
            + usernameReserved
            + " was reserved for another worker with ID "
            + recepientWorkerID
        )


# Fired when the worker receives a message of type "user_was_released"
# Do not insert wait, sleeps, locks or semaphores acquires in listeners;
# Instead, spawn a dedicated thread    
def masterReleasedUserListener(environment, msg, **kwargs):
    global workerID
    recepientWorkerID = msg.data["workerID"] 
    usernameReleased = msg.data["username"]
    if (workerID == recepientWorkerID):
        logging.debug("Worker received ack that user " 
            + usernameReleased
            + " was released by master"
        )
    else:
        logging.debug("Worker received message from master that user " 
            + usernameReleased
            + " was released after request of another worker with ID "
            + recepientWorkerID
        )


# Fired when the worker receives a message of type "policy_was_reserved"
# Do not insert wait, sleeps, locks or semaphores acquires in listeners;
# Instead, spawn a dedicated thread    
def masterReservedPolicyListener(environment, msg, **kwargs):
    global workerID
    recepientWorkerID = msg.data["workerID"] 
    if (workerID == recepientWorkerID):
        t = threading.Thread(
            target=masterReservedPolicy
        )
        t.start()

    else:
        logging.debug("Worker received message from master that " 
            + "policy was reserved for another worker with ID "
            + recepientWorkerID
        )

# Task for masterReservedPolicyListener function
def masterReservedPolicy():
    global policySemaphore
    logging.debug("Worker received message from master, " 
        + "reserved policy, releasing semaphore"
    )
    WorkflowExecutor.reservePolicyLock.acquire()
    policySemaphore.release()
    policySemaphore = None
    WorkflowExecutor.reservePolicyLock.release()


# Fired when the worker receives a message of type "policy_was_released"
# Do not insert wait, sleeps, locks or semaphores acquires in listeners;
# Instead, spawn a dedicated thread
def masterReleasedPolicyListener(environment, msg, **kwargs):
    global workerID
    recepientWorkerID = msg.data["workerID"] 
    if (workerID == recepientWorkerID):
        logging.debug("Worker received ack that policy" 
            + " was released by master"
        )
    else:
        logging.debug("Worker received message from master that policy " 
            + "was released after request of another worker with ID "
            + recepientWorkerID
        )


# Fired when the worker receives a message of type "policy_was_updated"
# Do not insert wait, sleeps, locks or semaphores acquires in listeners;
# Instead, spawn a dedicated thread    
def masterUpdatedPolicyListener(environment, msg, **kwargs):
    originalWorkerID = msg.data["workerID"] 
    updateType = msg.data["updateType"]
    masterTime = msg.data["masterTime"] 
    t = threading.Thread(
        target=masterUpdatedPolicy, 
        args=(originalWorkerID, updateType, masterTime, msg)
    )
    t.start()


# Task for masterUpdatedPolicyListener function
def masterUpdatedPolicy(originalWorkerID, updateType, masterTime, msg):
    global workerID, locustEnv, policySemaphore

    if (workerID != originalWorkerID):
        logging.debug(
            "Worker received message from master at time "
            + str(masterTime)
            + " that the policy was updated: op " 
            + updateType
        )
        BaseRBAC.policyLock.acquire()
        if (updateType == "wholePolicy"):
            BaseRBAC.usersU = msg.data["usersU"]
            BaseRBAC.rolesR = msg.data["rolesR"]
            BaseRBAC.resourcesF = msg.data["resourcesF"]
            BaseRBAC.assignmentsUR = msg.data["assignmentsUR"]
            BaseRBAC.permissionsPA = msg.data["permissionsPA"]
            logging.warn("Update: updating whole policy")
            BaseRBAC.acquiredACPolicyState = True
        else:
            if (not BaseRBAC.acquiredACPolicyState):
                logging.debug("Ignoring update, we still have to fetch the policy" )
            else:
                if (updateType == "addUser"):
                    username = msg.data["username"]
                    logging.debug("Update: adding user " + username)
                    BaseRBAC.usersU.append(username)
                elif (updateType == "addRole"):
                    roleName = msg.data["roleName"]
                    logging.debug("Update: adding role " + roleName)
                    BaseRBAC.rolesR.append(roleName)
                elif (updateType == "addResource"):
                    resourceName = msg.data["resourceName"]
                    logging.debug("Update: adding resource " + resourceName)
                    BaseRBAC.resourcesF.append(resourceName)
                elif (updateType == "deleteUser"):
                    username = msg.data["username"]
                    logging.debug("Update: deleting user " + username)
                    if (username in BaseRBAC.usersU):
                        BaseRBAC.usersU.remove(username)
                    for roleName in BaseRBAC.assignmentsUR:
                        if (username in BaseRBAC.assignmentsUR[roleName]):
                            BaseRBAC.assignmentsUR[roleName].remove(username)
                elif (updateType == "deleteRole"):
                    roleName = msg.data["roleName"]
                    logging.debug("Update: deleting role " + roleName)
                    if (roleName in BaseRBAC.rolesR):
                        BaseRBAC.rolesR.remove(roleName)
                    del BaseRBAC.assignmentsUR[roleName]
                    del BaseRBAC.permissionsPA[roleName]
                elif (updateType == "deleteResource"):
                    resourceName = msg.data["resourceName"]
                    logging.debug("Update: deleting resource " + resourceName)
                    if (resourceName in BaseRBAC.resourcesF):
                        BaseRBAC.resourcesF.remove(resourceName)
                    for roleName in BaseRBAC.permissionsPA:
                        for currentPermission in BaseRBAC.permissionsPA[roleName]:
                            if (currentPermission["resource"] == resourceName):
                                BaseRBAC.permissionsPA[roleName].remove(currentPermission)
                elif (updateType == "assignUser"):
                    username = msg.data["username"]
                    roleName = msg.data["roleName"] 
                    logging.debug("Update: assigning user " + username + " to role " + roleName)
                    BaseRBAC.assignmentsUR[roleName].append(username)
                elif (updateType == "assignPermission"):
                    roleName = msg.data["roleName"]
                    resourceName = msg.data["resourceName"]
                    permission = msg.data["permission"]
                    logging.debug("Update: assigning permission " + permission + " to role " + roleName + " over resource " + resourceName)
                    BaseRBAC.permissionsPA[roleName].append(({
                        "resource":resourceName, "permission":permission
                    }))
                elif (updateType == "revokeUser"):
                    username = msg.data["username"]
                    roleName = msg.data["roleName"]
                    logging.debug("Update: revoking user " + username + " from role " + roleName)
                    BaseRBAC.assignmentsUR[roleName].remove(username)
                elif (updateType == "revokePermission"):
                    resourceName = msg.data["resourceName"]
                    roleName = msg.data["roleName"]
                    logging.debug("Update: revoking permission on resource " + resourceName + " from role " + roleName)
                    for currentPermission in BaseRBAC.permissionsPA[roleName]:
                        if (currentPermission["resource"] == resourceName):
                            BaseRBAC.permissionsPA[roleName].remove(currentPermission)
                else:
                    message = "Worker " + workerID + ": receive unexpected policy update type " + updateType
                    logging.error(message)
                    raise InvalidFileException(message)
        BaseRBAC.policyLock.release()
    #else:
    #    WorkflowExecutor.reservePolicyLock.acquire()
    #    policySemaphore = None
    #    WorkflowExecutor.reservePolicyLock.release()
    logging.debug("Worker: sending ack of policy update to master")
    locustEnv.runner.send_message(
        'ack_policy', 
        {
            "workerID":workerID
        }
    )
        

# Fired when the master receives a message of type "reserve_user"
# Do not insert wait, sleeps, locks or semaphores acquires in listeners;
# Instead, spawn a dedicated thread    
def workerAskToReserveUserListener(environment, msg, **kwargs):
    senderWorkerID = msg.data["workerID"] 
    usernameToReserve = msg.data["username"]
    logging.info("Master received message from worker "
        + senderWorkerID
        + "; worker asked to reserve user " 
        + usernameToReserve
    )
    t = threading.Thread(
        target=workerAskToReserveUser, 
        args=(senderWorkerID, usernameToReserve)
    )
    t.start()
    

# Task for workerAskToReserveUserListener function
def workerAskToReserveUser(senderWorkerID, usernameToReserve):
    global masterUsersLock, usersReserved, locustEnv, workersUserRequests
    
    masterUsersLock.acquire()
    if (usernameToReserve in usersReserved):
        workersUserRequests[usernameToReserve].append(senderWorkerID)
        masterUsersLock.release()
        logging.info("Master: user "
            + usernameToReserve
            + " is already being used by another"
            + " worker"
        )
    else:
        usersReserved.append(usernameToReserve)
        workersUserRequests[usernameToReserve] = []
        masterUsersLock.release()
        logging.info("Master: reserved user "
            + usernameToReserve
            + " for worker "
            + senderWorkerID
            + "; sending message to worker"
        )
        locustEnv.runner.send_message(
            'user_was_reserved', 
            {
                "username":usernameToReserve,
                "workerID":senderWorkerID
            }
        )


# Fired when the master receives a message of type "release_user"
# Do not insert wait, sleeps, locks or semaphores acquires in listeners;
# Instead, spawn a dedicated thread    
def workerAskToReleaseUserListener(environment, msg, **kwargs):

    senderWorkerID = msg.data["workerID"] 
    usernameToRelease = msg.data["username"]
    logging.info("Master received message from worker "
        + senderWorkerID
        + "; worker asked to release user " 
        + usernameToRelease
    )
    t = threading.Thread(
        target=workerAskToReleaseUser, 
        args=(senderWorkerID, usernameToRelease)
    )
    t.start()


# Task for workerAskToReleaseUserListener function
def workerAskToReleaseUser(senderWorkerID, usernameToRelease):
    global masterUsersLock, usersReserved, locustEnv, workersUserRequests
    
    masterUsersLock.acquire()
    if (len(workersUserRequests[usernameToRelease]) == 0):
        usersReserved.remove(usernameToRelease)
        del workersUserRequests[usernameToRelease]
        masterUsersLock.release()
        locustEnv.runner.send_message(
            'user_was_released', 
            {
                "username":usernameToRelease,
                "workerID":senderWorkerID
            }
        )
    else:
        nextWorkerID = workersUserRequests[usernameToRelease][0]
        workersUserRequests[usernameToRelease].pop(0)
        masterUsersLock.release()
        logging.info("Master: do not release user "
            + usernameToRelease
            + ", but reserve it for next worker "
            + nextWorkerID
            + "; sending message to worker"
        )
        locustEnv.runner.send_message(
            'user_was_reserved', 
            {
                "username":usernameToRelease,
                "workerID":nextWorkerID
            }
        )


# Fired when the master receives a message of type "reserve_policy"
# Do not insert wait, sleeps, locks or semaphores acquires in listeners;
# Instead, spawn a dedicated thread    
def workerAskToReservePolicyListener(environment, msg, **kwargs):
    senderWorkerID = msg.data["workerID"] 
    logging.info("Master received message from worker "
        + senderWorkerID
        + "; worker asked to reserve policy" 
    )
    t = threading.Thread(
        target=workerAskToReservePolicy, 
        args=(senderWorkerID,)
    )
    t.start()
    

# Task for workerAskToReservePolicyListener function
def workerAskToReservePolicy(senderWorkerID):
    global masterPolicyLock, policyReserved, locustEnv, workersPolicyRequests
    
    masterPolicyLock.acquire()
    if (policyReserved):
        workersPolicyRequests.append(senderWorkerID)
        masterPolicyLock.release()
        logging.info("Master: policy is already being used by another worker")
    else:
        policyReserved = True
        masterPolicyLock.release()
        logging.info("Master: reserved policy for worker "
            + senderWorkerID
            + "; sending message to worker"
        )
        locustEnv.runner.send_message(
            'policy_was_reserved', 
            {
                "workerID":senderWorkerID
            }
        )


# Fired when the master receives a message of type "release_policy"
# Do not insert wait, sleeps, locks or semaphores acquires in listeners;
# Instead, spawn a dedicated thread    
def workerAskToReleasePolicyListener(environment, msg, **kwargs):

    senderWorkerID = msg.data["workerID"] 
    logging.info("Master received message from worker "
        + senderWorkerID
        + "; worker asked to release policy" 
    )
    t = threading.Thread(
        target=workerAskToReleasePolicy, 
        args=(senderWorkerID,)
    )
    t.start()


# Task for workerAskToReleasePolicyListener function
def workerAskToReleasePolicy(senderWorkerID):
    global masterPolicyLock, policyReserved, locustEnv, workersPolicyRequests
    
    masterPolicyLock.acquire()
    if (len(workersPolicyRequests) == 0):
        policyReserved = False
        masterPolicyLock.release()
        locustEnv.runner.send_message(
            'policy_was_released', 
            {
                "workerID":senderWorkerID
            }
        )
    else:
        nextWorkerID = workersPolicyRequests[0]
        workersPolicyRequests.pop(0)
        masterPolicyLock.release()
        logging.info("Master: do not release policy"
            + ", but reserve it for next worker "
            + nextWorkerID
            + "; sending message to worker"
        )
        locustEnv.runner.send_message(
            'policy_was_reserved', 
            {
                "workerID":nextWorkerID
            }
        )


# Fired when the master receives a message of type "update_policy"
# Do not insert wait, sleeps, locks or semaphores acquires in listeners;
# Instead, spawn a dedicated thread    
def workerAskToUpdatePolicyListener(environment, msg, **kwargs):
    global syncPolicyAcrossWorkers
    senderWorkerID = msg.data["workerID"] 
    updateType = msg.data["updateType"]
    ts = str(datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S %f"))
    msg.data["masterTime"] = ts
    logging.debug("Master received message from worker "
        + senderWorkerID
        + "at time "
        + ts
        + "; worker updated the policy with op " 
        + updateType
    )
    # This is a message from the first worker that acquired the policy state
    if (updateType == "wholePolicy"):
        logging.warn("Updating the whole policy")
        t = threading.Thread(
            target=workerAskToUpdatePolicy, 
            args=(msg.data,)
        )
        t.start()
    elif (syncPolicyAcrossWorkers):
        t = threading.Thread(
            target=workerAskToUpdatePolicy, 
            args=(msg.data,)
        )
        t.start()
    else:
        t = threading.Thread(
            target=workerAskToReleasePolicy, 
            args=(senderWorkerID,)
        )
        t.start()


# Task for workerAskToUpdatePolicyListener function
def workerAskToUpdatePolicy(data):
    global locustEnv, acksOfPolicyUpdateToReceive
    logging.debug("Master: sending 'policy_was_updated' message to workers "
        + "to then collect the acks and finally release the policy"
    )
    acksOfPolicyUpdateToReceive = set()
    locustEnv.runner.send_message(
        'policy_was_updated', 
        data
    )


# Fired when the master receives a message of type "ack_policy"
# Do not insert wait, sleeps, locks or semaphores acquires in listeners;
# Instead, spawn a dedicated thread    
def workerAckPolicyListener(environment, msg, **kwargs):
    global acksOfPolicyUpdateToReceive, masterPolicyLock, numberOfWorkers
    workerID = msg.data["workerID"]
    logging.debug("Master received ack from worker "
        + workerID
    )
    masterPolicyLock.acquire()
    acksOfPolicyUpdateToReceive.add(workerID)
    if (len(acksOfPolicyUpdateToReceive) == numberOfWorkers):
        masterPolicyLock.release()
        logging.debug("Master received acks from all workers; releasing policy")
        t = threading.Thread(
            target=workerAskToReleasePolicy, 
            args=("MASTER",)
        )
        t.start()
    else:
        masterPolicyLock.release()
        

# Fired when the master receives a message of type "stop_execution"
# Do not insert wait, sleeps, locks or semaphores acquires in listeners;
# Instead, spawn a dedicated thread    
def workerAskToStopExecutionListener(environment, msg, **kwargs):
    senderWorkerID = msg.data["workerID"] 
    logging.error("Master received message from worker "
        + senderWorkerID
        + "; worker had error, asked to stop execution " 
    )
    environment.runner.quit()


# Custome command line arguments
@events.init_command_line_parser.add_listener
def _(parser):

    parser.add_argument(
        "--operations", 
        type=str, 
        help="Path to one or more .json files separated by a ';' produced by the workflow extraction procedure and containing the lists of access control operations (e.g., 'path/to/file/1.json;path/to/file_2.json')."
    )

    parser.add_argument(
        "--adapter", 
        type=str,
        help="The adapter to use among 'CryptoAC', 'OPA', 'OPAWithDM', 'XACML' and 'XACMLWithDM'. Please refer to the implementation of each adapter for more details. Note that other adapters can be easily implemented (follow the instructions in the 'BaseRBAC' class)."
    )

    parser.add_argument(
        '--doInitialize', 
        action='store_true',
        help="Whether the adapter needs to be initialized. In other words, if this option is specified, the 'initialize' method of the adapter (of each Locust instance) will be invoked. Usually, this option is specified when invoking the initializer (thus, not here).",
        include_in_web_ui=False
    )

    parser.add_argument(
        "-i",
        "--iterations",
        type=int,
        help="Run at most this number of task iterations (i.e., do at most this number of executions across all workflows) and terminate once they have finished. Warning: it is recommended to set a time limit instead of an iteration limit (i.e., use the '-t' option. For instance, a 20 minute time limit can be specified as '-t 20m')",
        env_var="LOCUST_ITERATIONS",
        default=0,
    )

    parser.add_argument(
        '--shuffle', 
        action='store_true',
        help='Choose a random execution in the current workflow at each task. By default, execute paths sequentially (recommended for reproducibility). Workflows are always executed sequentially',
        include_in_web_ui=False
    )
        
    parser.add_argument(
        "--repeatWorkflows", 
        type=str,
        help="How many times to repeat each workflow before automatically terminating the load test (by default, repetitions are infinite). Warning: it is recommended to set a time limit instead of a repetition limit (i.e., use the '-t' option. For instance, a 20 minute time limit can be specified as '-t 20m')",
        include_in_web_ui=False
    )

    parser.add_argument(
        "--workerID", 
        type=str,
        help="The ID of this worker (used for, e.g., logs and names). Default is random string of length 10. It is suggested to not modify the default (i.e., do not specify this option unless you know what you are doing)",
        include_in_web_ui=False
    )

    parser.add_argument(
        "--numberOfWorkers", 
        type=str,
        help="The total number of workers, i.e., how many Locust worker instances will simultaneously interact with the mechanism. Warning: this option should always be synchronized with the options '--expect-workers' and '-u' ",
        include_in_web_ui=False
    )
        
    parser.add_argument(
        "--reserveUsers", 
        action='store_true',
        help="Reserve users for executing operations (recommended). Otherwise, the same user(name) may end up doing several times concurrently (potentially leading to consistency issues)",
        include_in_web_ui=False
    )

    parser.add_argument(
        "--ignoreAddUser", 
        action='store_true',
        help="Ignore add user operations",
        include_in_web_ui=False
    )
         
    parser.add_argument(
        "--ignoreAddRole", 
        action='store_true',
        help="Ignore add role operations",
        include_in_web_ui=False
    )
            
    parser.add_argument(
        "--ignoreAddResource", 
        action='store_true',
        help="Ignore add resource operations",
        include_in_web_ui=False
    )
            
    parser.add_argument(
        "--ignoreDeleteUser", 
        action='store_true',
        help="Ignore delete user operations",
        include_in_web_ui=False
    )
            
    parser.add_argument(
        "--ignoreDeleteRole", 
        action='store_true',
        help="Ignore delete role operations",
        include_in_web_ui=False
    )
            
    parser.add_argument(
        "--ignoreDeleteResource", 
        action='store_true',
        help="Ignore delete resource operations",
        include_in_web_ui=False
    )
            
    parser.add_argument(
        "--ignoreAssignUser", 
        action='store_true',
        help="Ignore assign user (to role) operations",
        include_in_web_ui=False
    )
                
    parser.add_argument(
        "--ignoreAssignPermission", 
        action='store_true',
        help="Ignore assign role (to resource) operations",
        include_in_web_ui=False
    )
                
    parser.add_argument(
        "--ignoreRevokeUser", 
        action='store_true',
        help="Ignore revoke user (from role) operations",
        include_in_web_ui=False
    )
                
    parser.add_argument(
        "--ignoreRevokePermission", 
        action='store_true',
        help="Ignore revoke role (from resource) operations",
        include_in_web_ui=False
    )
                
    parser.add_argument(
        "--ignoreReadResource", 
        action='store_true',
        help="Ignore read resource operations",
        include_in_web_ui=False
    )
                
    parser.add_argument(
        "--ignoreWriteResource", 
        action='store_true',
        help="Ignore write resource operations",
        include_in_web_ui=False
    )    

    parser.add_argument(
        "--ignorePersistentAssignRevokePermission", 
        action='store_true',
        help="Ignore assign and revoke permissions on persistent resources",
        include_in_web_ui=False
    )

    parser.add_argument(
        "--uniqueUserNames", 
        action='store_true',
        help="Make that user names are unique to the workflow instance. Warning: specifying this option may break the experimentation (i.e., do not specify this option unless you know what you are doing)",
        include_in_web_ui=False
    )

    parser.add_argument(
        "--uniqueRoleNames", 
        action='store_true',
        help="Make that role names are unique to the workflow instance. Warning: specifying this option may break the experimentation (i.e., do not specify this option unless you know what you are doing. This option may clash with the 'ignoreAddRole' option)",
        include_in_web_ui=False
    )

    parser.add_argument(
        "--uniqueTransientResourceNames", 
        action='store_true',
        help="Make that transient resource names are unique to the workflow instance (recommended). You may set this option to avoid two or more workers to create resources with the same name",
        include_in_web_ui=False
    )

    parser.add_argument(
        "--reservePolicy", 
        action='store_true',
        help="Whether to make Locust workers ask the Locust master exclusive access to the state of the access control policy. In other words, this option makes that modifications to the policy are sequential, not concurrent. This may avoid inconsistency issues deriving from the fact that the policy is modified by multiple workers",
        include_in_web_ui=False
    )

    parser.add_argument(
        "--syncPolicyAcrossWorkers", 
        action='store_true',
        help="Whether to syncrhonize the access control policy state across workers (this option requires the 'reservePolicy' option)",
        include_in_web_ui=False
    )

    


# Register listeners for messages exchanged 
# between the Locust workers and the master
@events.init.add_listener
def register_listeners(environment, **_kwargs):
    # save the environment reference
    global locustEnv
    locustEnv = environment

    # register message listeners for messages sent 
    # by the master and received by the workers
    if not isinstance(environment.runner, MasterRunner):
        environment.runner.register_message('user_was_reserved', masterReservedUserListener)
        environment.runner.register_message('user_was_released', masterReleasedUserListener)
        environment.runner.register_message('policy_was_reserved', masterReservedPolicyListener)
        environment.runner.register_message('policy_was_released', masterReleasedPolicyListener)
        environment.runner.register_message('policy_was_updated', masterUpdatedPolicyListener)

    # register message listeners for messages sent 
    # by the workers and received by the master
    if not isinstance(environment.runner, WorkerRunner):
        environment.runner.register_message('reserve_user', workerAskToReserveUserListener)
        environment.runner.register_message('release_user', workerAskToReleaseUserListener)
        environment.runner.register_message('reserve_policy', workerAskToReservePolicyListener)
        environment.runner.register_message('release_policy', workerAskToReleasePolicyListener)
        environment.runner.register_message('update_policy', workerAskToUpdatePolicyListener)
        environment.runner.register_message('ack_policy', workerAckPolicyListener)
        environment.runner.register_message('stop_execution', workerAskToStopExecutionListener)


# Took from locust plugins (https://github.com/SvenskaSpel/locust-plugins/blob/master/locust_plugins/__init__.py)
# to avoid having to import all plugins
# Setup the maximum number of iterations per task
@events.test_start.add_listener
def set_up_iteration_limit(environment: Environment, **kwargs):
    options = environment.parsed_options
    if options.iterations:
        runner: Runner = environment.runner
        runner.iterations_started = 0
        runner.iteration_target_reached = False

        def iteration_limit_wrapper(method):
            @wraps(method)
            def wrapped(self, task):
                if runner.iterations_started == options.iterations:
                    if not runner.iteration_target_reached:
                        runner.iteration_target_reached = True
                        logging.info(
                            f"Iteration limit reached ({options.iterations}), stopping Users at the start of their next task run"
                        )
                    if runner.user_count == 1:
                        logging.info("Last user stopped, quitting runner")
                        runner.quit()
                    raise StopUser()
                runner.iterations_started = runner.iterations_started + 1
                method(self, task)

            return wrapped

        # monkey patch TaskSets to add support for iterations limit. Not ugly at all :)
        TaskSet.execute_task = iteration_limit_wrapper(TaskSet.execute_task)
        DefaultTaskSet.execute_task = iteration_limit_wrapper(DefaultTaskSet.execute_task)


# Execute before starting the load test
# Acquire command line arguments
@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    global numberOfWorkers, syncPolicyAcrossWorkers, adapterToUse, workflowsAndPaths, doInitialize, host, shuffle, workerID, reservePolicy, uniqueUserNames, uniqueRoleNames, uniqueTransientResourceNames, reserveUsers, ignoreAddUser, ignoreAddRole, ignoreAddResource, ignoreDeleteUser, ignoreDeleteRole, ignoreDeleteResource, ignoreAssignUser, ignoreAssignPermission, ignoreRevokeUser, ignoreRevokePermission, ignoreReadResource, ignoreWriteResource, ignorePersistentAssignRevokePermission, repeatWorkflows, numberOfRepetitionsPerPathByWorkflow, numberOfPathsPerWorkflow

    host = os.environ['host'] if ('host' in os.environ) else environment.host
    args = environment.parsed_options

    if ('workerID' in os.environ):
        workerID = os.environ['workerID'] 
    elif (args.workerID):
        workerID = args.workerID
    else:
        workerID = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    logging.info("Worker ID is " + workerID)

    logging.info(
        """
            ______            _          
           / ____/___  ____ _(_)___  ___ 
          / __/ / __ \/ __ `/ / __ \/ _ \\
         / /___/ / / / /_/ / / / / /  __/
        /_____/_/ /_/\__, /_/_/ /_/\___/ 
                    /____/                                                                  
        """ +
        "(worker ID: " +
        str(workerID) +
        ")"
    )

    logging.warn("""
        __          __     _____  _   _ _____ _   _  _____ 
         \ \        / /\   |  __ \| \ | |_   _| \ | |/ ____|
          \ \  /\  / /  \  | |__) |  \| | | | |  \| | |  __ 
           \ \/  \/ / /\ \ |  _  /| . ` | | | | . ` | | |_ |
            \  /\  / ____ \| | \ \| |\  |_| |_| |\  | |__| |
             \/  \/_/    \_\_|  \_\_| \_|_____|_| \_|\_____|
                                                            
        When running Locust distributed, custom arguments are automatically forwarded from the master
        to the workers when the run is started (but not before then, so you cannot rely on forwarded 
        arguments before the test has actually started).

        As a corollary, if you want to customize the arguments worker-wise (i.e., give to workers different 
        values for the same argument, pass those arguments as environment variables instead that as arguments

        For instance, to specify a custom host, run:
            env host=https://127.0.0.1:80 locust -f simulator/Engine.py --worker
        Instead of 
            locust -f simulator/Engine.py --worker --host=https://127.0.0.1:80
        """
    )

    reserveUsers = os.environ['reserveUsers'] if ('reserveUsers' in os.environ) else args.reserveUsers
    ignoreAddUser = os.environ['ignoreAddUser'] if ('ignoreAddUser' in os.environ) else args.ignoreAddUser
    ignoreAddRole = os.environ['ignoreAddRole'] if ('ignoreAddRole' in os.environ) else args.ignoreAddRole
    ignoreAddResource = os.environ['ignoreAddResource'] if ('ignoreAddResource' in os.environ) else args.ignoreAddResource
    ignoreDeleteUser = os.environ['ignoreDeleteUser'] if ('ignoreDeleteUser' in os.environ) else args.ignoreDeleteUser
    ignoreDeleteRole = os.environ['ignoreDeleteRole'] if ('ignoreDeleteRole' in os.environ) else args.ignoreDeleteRole
    ignoreDeleteResource = os.environ['ignoreDeleteResource'] if ('ignoreDeleteResource' in os.environ) else args.ignoreDeleteResource
    ignoreAssignUser = os.environ['ignoreAssignUser'] if ('ignoreAssignUser' in os.environ) else args.ignoreAssignUser
    ignoreAssignPermission = os.environ['ignoreAssignPermission'] if ('ignoreAssignPermission' in os.environ) else args.ignoreAssignPermission
    ignoreRevokeUser = os.environ['ignoreRevokeUser'] if ('ignoreRevokeUser' in os.environ) else args.ignoreRevokeUser
    ignoreRevokePermission = os.environ['ignoreRevokePermission'] if ('ignoreRevokePermission' in os.environ) else args.ignoreRevokePermission
    ignoreReadResource = os.environ['ignoreReadResource'] if ('ignoreReadResource' in os.environ) else args.ignoreReadResource
    ignoreWriteResource = os.environ['ignoreWriteResource'] if ('ignoreWriteResource' in os.environ) else args.ignoreWriteResource
    ignorePersistentAssignRevokePermission = os.environ['ignorePersistentAssignRevokePermission'] if ('ignorePersistentAssignRevokePermission' in os.environ) else args.ignorePersistentAssignRevokePermission
    uniqueUserNames = os.environ['uniqueUserNames'] if ('uniqueUserNames' in os.environ) else args.uniqueUserNames
    uniqueRoleNames = os.environ['uniqueRoleNames'] if ('uniqueRoleNames' in os.environ) else args.uniqueRoleNames
    uniqueTransientResourceNames = os.environ['uniqueTransientResourceNames'] if ('uniqueTransientResourceNames' in os.environ) else args.uniqueTransientResourceNames
    reservePolicy = os.environ['reservePolicy'] if ('reservePolicy' in os.environ) else args.reservePolicy
    syncPolicyAcrossWorkers = os.environ['syncPolicyAcrossWorkers'] if ('syncPolicyAcrossWorkers' in os.environ) else args.syncPolicyAcrossWorkers

    if (syncPolicyAcrossWorkers and not reservePolicy):
        logging.error("The 'syncPolicyAcrossWorkers' flag requires the 'reservePolicy' flag")

    shuffle = os.environ['shuffle'] if ('shuffle' in os.environ) else args.shuffle
    doInitialize = os.environ['doInitialize'] if ('doInitialize' in os.environ) else args.doInitialize
    operations = os.environ['operations'] if ('operations' in os.environ) else args.operations
    operationFiles = operations.split(";")
    logging.info("Worker with ID " + str(workerID) + " has " + str(host) + " as host")
    logging.info("Worker with ID " + str(workerID) + " has " + str(len(operationFiles)) + " operation files")

    for operationFile in operationFiles:
        if (not os.path.isfile(operationFile)):
            logging.error("File " + operationFile + " not found")
            exit(1)
        else:
            logging.info(" - " + operationFile)

    numberOfWorkers = int(os.environ['numberOfWorkers']) if ('numberOfWorkers' in os.environ) else int(args.numberOfWorkers)

    if ('repeatWorkflows' in os.environ):
        repeatWorkflows = int(os.environ['repeatWorkflows'])
    elif (args.repeatWorkflows):
        repeatWorkflows = int(args.repeatWorkflows)
    else:
        repeatWorkflows = None
    if (repeatWorkflows != None):
        assert(repeatWorkflows > 0)

    for operationFile in operationFiles:
        with open(operationFile, "r") as fileReader:
            operationsJson = json.loads(fileReader.read())
            workflowName = operationsJson["name"]
            paths = operationsJson["paths"]
            numberOfPaths = len(paths)
            workflowsAndPaths[workflowName] = paths
            numberOfPathsPerWorkflow[workflowName] = numberOfPaths
            latestPathExecutedIndexPerWorkflow[workflowName] = 0
            numberOfRepetitionsPerPathByWorkflow[workflowName] = {} 
            for path in paths:
                numberOfRepetitionsPerPathByWorkflow[workflowName][path["pathID"]] = 0
            if (numberOfPaths == 0):
                message = "Workflow " + workflowName + ": no paths to execute!"
                logging.error(message)
                raise InvalidFileException(message)
            elif (numberOfPaths == 1):
                logging.info("Workflow " + workflowName + ": 1 path to execute")
            else:
                logging.info("Workflow " + workflowName + ": " + str(numberOfPaths) + " paths to execute")

    adapterToUse = os.environ['adapter'] if ('adapter' in os.environ) else args.adapter
    if (adapterToUse == "CryptoAC"):
        logging.info("Chose CryptoAC as adapter")
    elif (adapterToUse == "CryptoACMQTT"):
        logging.info("Chose CryptoACMQTT as adapter")
    elif (adapterToUse == "OPA"):
        logging.info("Chose OPA as adapter")
    elif (adapterToUse == "OPAWithDM"):
        logging.info("Chose OPAWithDM as adapter")
    elif (adapterToUse == "XACML"):
        logging.info("Chose XACML as adapter")
    elif (adapterToUse == "XACMLWithDM"):
        logging.info("Chose XACMLWithDM as adapter")
    else:
        message = "Adapter " + adapterToUse + " not supported"
        logging.error(message)
        raise UnsupportedOperation(message)


# Execute before stopping the load test
# Log end of test
@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    logging.info("A test is ending. You can now collect the results")


# Class implementing the execution of the workflow
class WorkflowExecutor(HttpUser):
    wait_time = constant(0)
    chooseWorkflowLock = threading.Lock()
    reserveUserLock = threading.Lock()
    reservePolicyLock = threading.Lock()
    adapter = None

    # Time spent idling (usually, waiting for users 
    # to be available to execute operations)
    idlingTime = 0


    # A User will call its on_start method when it starts running
    def on_start(self):
        self.adapter = getInstanceOfAdapter(
            username = BaseRBAC.adminName
        )

        # Do not verity TLS certificates
        self.client.verify = False
        self.adapter.setClient(self.client)
        sendWholePolicyUpdate = not BaseRBAC.acquiredACPolicyState
        self.askMasterToReservePolicy(forceReserve = sendWholePolicyUpdate)
        self.adapter.on_start()
        if (sendWholePolicyUpdate):
            self.notifyMasterOfPolicyUpdate({ 
                "usersU":BaseRBAC.usersU,
                "rolesR":BaseRBAC.rolesR,
                "resourcesF":BaseRBAC.resourcesF,
                "assignmentsUR":BaseRBAC.assignmentsUR,
                "permissionsPA":BaseRBAC.permissionsPA,
                "updateType":"wholePolicy"
            })
        else:
            self.notifyMasterToReleasePolicy()
            


    # A User will call its on_stop method when it stops running
    def on_stop(self):
        self.adapter.on_stop()


    # Assert success for the path
    def assertSuccess(self, pathID, booleanValue):
        global locustEnv
        if (not booleanValue):
            logging.error("Path with ID " 
                + pathID
                + " had operation with error, abort "
                + "(client ID is "
                + str(self.client.cookies.get_dict())
                + ")"
            )
            logging.error("Traceback is below: ")
            traceback.print_stack()
            locustEnv.runner.send_message(
                'stop_execution', 
                {
                    "workerID":workerID
                }
            )
            sys.exit(1)


    # Ask the Locust master to reserve the policy
    # for modifications. Lock while waiting, return 
    # when the master granted permission to modify 
    # the policy
    def askMasterToReservePolicy(self, period = 0.010, forceReserve = False):
        global locustEnv, policySemaphore, workerID, reservePolicy
        if (reservePolicy or forceReserve):
            startTime = time.time()
            logging.debug("Asking master to reserve policy")

            # Lock to exclusively create the semaphore to modify the policy
            WorkflowExecutor.reservePolicyLock.acquire()

            # if so, it means that this worker has already
            # requested the policy. Therefore, release the 
            # lock, wait, acquire the lock and try again
            sleepTime = 0
            while (policySemaphore != None):
                WorkflowExecutor.reservePolicyLock.release()
                sleepTime = sleepTime + period
                if (sleepTime == 10):
                    logging.debug("Another user of this worker is already waiting for " 
                        + "permission from the master to modify the policy. Sleep "
                        + str(period)
                        + " seconds and then try again"
                    )
                    sleepTime = 0
                time.sleep(period)
                WorkflowExecutor.reservePolicyLock.acquire()

            # If we reached this point, it means that we are
            # absolutely sure that the policy has not already 
            # been requested by this worker. Therefore, create
            # the corresponding semaphore (so that this worker
            # cannot reach this point anymore), release the lock,
            # ask the master for the policy and then acquire the
            # semaphore, waiting for the master to answer
            policySemaphore = Semaphore(0)
            WorkflowExecutor.reservePolicyLock.release()
            locustEnv.runner.send_message(
                'reserve_policy', 
                {
                    "workerID":workerID
                }
            )
            logging.debug("Sent message, not wait semaphore release")
            policySemaphore.acquire()

            idledTime = time.time() - startTime
            self.idlingTime += idledTime

            logging.debug("Successfully reserved policy (idled "
                + str(idledTime*1000)
                + " milliseconds)"
            )
        else:
            logging.debug("Do not reserve policy")
        return


    # Ask the Locust master to reserve a user belonging
    # to the given roleName. Return the reserved username
    def askMasterToReserveUserBelongingToRole(self, roleName):
        if (roleName == BaseRBAC.adminName and BaseRBAC.adminName not in BaseRBAC.assignmentsUR):
            return self.askMasterToReserveUser(BaseRBAC.adminName)
        else:
            userToAskToReserve = self.adapter.getRandomUserFromRole(roleName)
            return self.askMasterToReserveUser(userToAskToReserve)


    # Ask the Locust master to reserve the 
    # given user. Lock while waiting, return 
    # the reserved username when available
    def askMasterToReserveUser(self, username, period = 0.010):
        global locustEnv, userSemaphores, workerID, reserveUsers
        if (reserveUsers):
            startTime = time.time()
            logging.debug("Asking master to reserve user " + username)

            # Lock to exclusively create the semaphore corresponding to
            # the user that this worker wants to ask the master to reserve
            WorkflowExecutor.reserveUserLock.acquire()

            # if so, it means that this worker has already
            # requested the user. Therefore, release the 
            # lock, wait, acquire the lock and try again
            sleepTime = 0
            while (username in userSemaphores):
                WorkflowExecutor.reserveUserLock.release()
                sleepTime = sleepTime + period
                if (sleepTime == 10):
                    logging.debug("Another user of this worker is already waiting for user " 
                        + username
                        + ". Sleep "
                        + str(period)
                        + " seconds and then try again"
                    )
                    sleepTime = 0
                time.sleep(period)
                WorkflowExecutor.reserveUserLock.acquire()

            # If we reached this point, it means that we are
            # absolutely sure that the user has not already 
            # been requested by this worker. Therefore, create
            # the corresponding semaphore (so that this worker
            # cannot reach this point anymore), release the lock,
            # ask the master for the user and then acquire the
            # semaphore, waiting for the master to answer
            userSemaphores[username] = Semaphore(0)
            WorkflowExecutor.reserveUserLock.release()
            locustEnv.runner.send_message(
                'reserve_user', 
                {
                    "username":username,
                    "workerID":workerID
                }
            )
            logging.debug("Sent message, not wait semaphore release")
            userSemaphores[username].acquire()

            idledTime = time.time() - startTime
            self.idlingTime += idledTime

            logging.debug("Successfully reserved user " 
                + username 
                + " (idled "
                + str(idledTime*1000)
                + " milliseconds)"
            )
        else:
            logging.debug("Do not reserving user " + username)
        return username


    # Notify the master to update the policy
    def notifyMasterOfPolicyUpdate(self, data):
        global locustEnv, workerID, reservePolicy
        wholeUpdate = data["updateType"] == "wholePolicy"
        if (reservePolicy or wholeUpdate):
            if (wholeUpdate):
                logging.warn("Notifying master to update whole policy")
            else:
                logging.debug("Notifying master to update policy")
            data["workerID"] = workerID
            locustEnv.runner.send_message(
                'update_policy', 
                data
            )
        else:
            logging.debug("Do not notify master of policy update")


    # Notify the master to release the user
    def notifyMasterToReleaseUser(self, userToRelease):
        global locustEnv, userSemaphores, workerID, reserveUsers
        if (reserveUsers):
            startTime = time.time()
            logging.debug("Notifying master to release user " + userToRelease)
            WorkflowExecutor.reserveUserLock.acquire()
            del userSemaphores[userToRelease]
            WorkflowExecutor.reserveUserLock.release()
            locustEnv.runner.send_message(
                'release_user', 
                {
                    "username":userToRelease,
                    "workerID":workerID
                }
            )
            idledTime = time.time() - startTime
            self.idlingTime += idledTime


    # Notify the master to release the policy
    def notifyMasterToReleasePolicy(self):
        global locustEnv, policySemaphore, workerID
        startTime = time.time()
        logging.debug("Notifying master to release the policy")
        WorkflowExecutor.reservePolicyLock.acquire()
        policySemaphore = None
        WorkflowExecutor.reservePolicyLock.release()
        locustEnv.runner.send_message(
            'release_policy', 
            {
                "workerID":workerID
            }
        )
        idledTime = time.time() - startTime
        self.idlingTime += idledTime


    # From the documentation: "you don't need SequentialTaskSets 
    # to just do some requests in order. It is often easier to
    # just do a whole user flow in a single task."
    @task
    def executeWorkflow(self):
        global syncPolicyAcrossWorkers, locustEnv, workflowsAndPaths, shuffle, uniqueUserNames, uniqueRoleNames, uniqueTransientResourceNames, reserveUsers, ignoreAddUser, ignoreAddRole, ignoreAddResource, ignoreDeleteUser, ignoreDeleteRole, ignoreDeleteResource, ignoreAssignUser, ignoreAssignPermission, ignoreRevokeUser, ignoreRevokePermission, ignoreReadResource, ignoreWriteResource, ignorePersistentAssignRevokePermission, workerID, repeatWorkflows, numberOfRepetitionsPerPathByWorkflow, latestPathExecutedIndexPerWorkflow, latestWorkflowExecutedIndex, numberOfPathsPerWorkflow

        WorkflowExecutor.chooseWorkflowLock.acquire()
        
        # Choose which workflow to execute (always choose linearly)
        workflow = None
        workflowNames = list(workflowsAndPaths.keys())
        while (workflowsAndPaths and workflow == None):
            workflow = workflowNames[latestWorkflowExecutedIndex]
            numberOfTimeWorkflowWasRepeated = sum(numberOfRepetitionsPerPathByWorkflow[workflow].values())
            if (repeatWorkflows != None and numberOfTimeWorkflowWasRepeated >= repeatWorkflows):
                del workflowsAndPaths[workflow] 
                workflowNames.remove(workflow)
                workflow = None
                latestWorkflowExecutedIndex = latestWorkflowExecutedIndex % len(workflowNames)
            else:
                latestWorkflowExecutedIndex = (latestWorkflowExecutedIndex + 1) % len(workflowNames)
        
        # If the list of workflows is empty, terminate the execution
        if (workflow == None):
            WorkflowExecutor.chooseWorkflowLock.release()
            sys.exit(0)

        # Now choose which path to execute (based on the shuffle property)
        paths = workflowsAndPaths[workflow]
        path = None
        if (shuffle):
            path = random.choice(paths)
        else:
            path = paths[latestPathExecutedIndexPerWorkflow[workflow]]
            latestPathExecutedIndexPerWorkflow[workflow] = (latestPathExecutedIndexPerWorkflow[workflow] + 1) % numberOfPathsPerWorkflow[workflow]

        pathID = path["pathID"]
        numberOfRepetitionsPerPathByWorkflow[workflow][path["pathID"]] += + 1
        currentRunPath = numberOfRepetitionsPerPathByWorkflow[workflow][path["pathID"]]
        currentRunWorkflow = sum(numberOfRepetitionsPerPathByWorkflow[workflow].values())
        uniqueID = (
            "workerID_" + workerID + 
            "_workflowID_" + workflow +
            "_pathID_" + pathID + 
            "_currentRunWorkflow_" + str(currentRunWorkflow) + 
            "_currentRunPath_" + str(currentRunPath)
        )
        WorkflowExecutor.chooseWorkflowLock.release()


        # We found a path to execute, so execute it!
        logging.info("Executing workflow " 
            + workflow 
            + ", path with ID "
            + pathID
            + ", repetition of workflow "
            + str(currentRunWorkflow)
            + ", repetition of path "
            + str(currentRunPath)
            + " (unique ID: "
            + uniqueID
            + ")"
        )

        listOfACOperations = path["ops"]
        numberOfOperations = len(listOfACOperations)
        wpid = "Workflow " + workflow + ", path " + uniqueID
        if (numberOfOperations == 0):
            logging.warn(wpid + ": no operation to execute!")
        elif (numberOfOperations == 1):
            logging.info(wpid + ": 1 operation to execute")
        else:
            logging.info(wpid + ": " + str(numberOfOperations) + " operations to execute")

        # Get the start time before executing the workflow
        numberOfOperations = 0
        startTime = time.time()

        with self.client.rename_request(f"/workflow?id=[{uniqueID}]"):
            for operation in listOfACOperations:
                numberOfOperations += 1
                vertexNameOrID = operation["vertex"]
                op = operation["op"]
                measure = operation["measure"]
                
                logging.debug("Path " 
                    + uniqueID 
                    + ": executing operation " 
                    + op 
                    + " with vertex " 
                    + vertexNameOrID 
                    + " (measure: "
                    + str(measure)
                    + ")"
                )
                                    
                if (op == "addUser"):
                    username = operation["username"] + "_" + uniqueID if (uniqueUserNames and operation["username"] != BaseRBAC.adminName) else operation["username"]
                    if (ignoreAddUser):
                        logging.debug("Path " 
                            + uniqueID 
                            + ": skipping addUser operation, username = " 
                            + username
                        ) 
                    else:
                        logging.debug("Path " 
                            + uniqueID 
                            + ": addUser, username = " 
                            + username
                        )
                        self.askMasterToReservePolicy()
                        operationSuccess = self.adapter.addUser(
                            username = username,
                            measure = measure
                        )
                        self.assertSuccess(uniqueID, operationSuccess)
                        self.notifyMasterOfPolicyUpdate({ 
                            "username":username,
                            "updateType":op
                        })
                        
 
                elif (op == "addRole"):
                    roleName = operation["roleName"] + "_" + uniqueID if (uniqueRoleNames and operation["roleName"] != BaseRBAC.adminName) else operation["roleName"]
                    if (ignoreAddRole):
                        logging.debug("Path " 
                            + uniqueID 
                            + ": skipping addRole operation, roleName = " 
                            + roleName
                        ) 
                    else:
                        logging.debug("Path " 
                            + uniqueID 
                            + ": addRole, roleName = " 
                            + roleName
                        )
                        self.askMasterToReservePolicy()
                        operationSuccess = self.adapter.addRole(
                            roleName = roleName,
                            measure = measure
                        )
                        self.assertSuccess(uniqueID, operationSuccess)
                        self.notifyMasterOfPolicyUpdate({ 
                            "roleName":roleName,
                            "updateType":op
                        })
                        

                elif (op == "addResource"):
                    type = operation["type"]
                    resourceName = operation["resourceName"] + "_" + uniqueID if (type == "transient" and uniqueTransientResourceNames) else operation["resourceName"]
                    roleName = operation["roleName"] + "_" + uniqueID if (uniqueRoleNames and operation["roleName"] != BaseRBAC.adminName) else operation["roleName"]
                    if (ignoreAddResource):
                        logging.debug("Path " 
                            + uniqueID 
                            + ": skipping addResource operation, resourceName = " 
                            + resourceName
                        ) 
                    else:
                        resourceContent = getRandomString(
                            sizeInBytes = int(operation["resourceSize"])
                        )
                        logging.debug("Path " 
                            + uniqueID 
                            + ": addResource, resourceName = " 
                            + resourceName
                            + " as role with roleName = "
                            + roleName
                        )
                        self.askMasterToReservePolicy()
                        userToUse = self.askMasterToReserveUserBelongingToRole(roleName)
                        resourceContent = self.adapter.addResource(
                            resourceName = resourceName,
                            userToUse = userToUse,
                            assumedRoleName = roleName,
                            resourceContent = resourceContent,
                            measure = measure
                        )
                        self.notifyMasterToReleaseUser(userToUse)
                        if (resourceContent == True or resourceContent == False):
                            self.assertSuccess(uniqueID, resourceContent)
                        self.notifyMasterOfPolicyUpdate({ 
                            "resourceName":resourceName,
                            "updateType":op
                        })
 

                elif (op == "deleteUser"):
                    username = operation["username"] + "_" + uniqueID if (uniqueUserNames and operation["username"] != BaseRBAC.adminName) else operation["username"]
                    if (ignoreDeleteUser):
                        logging.debug("Path " 
                            + uniqueID 
                            + ": skipping deleteUser operation, username = " 
                            + username
                        ) 
                    else:
                        logging.debug("Path " 
                            + uniqueID 
                            + ": deleteUser, username = " 
                            + username
                        )
                        self.askMasterToReservePolicy()
                        operationSuccess = self.adapter.deleteUser(
                            username = username,
                            measure = measure
                        )
                        self.assertSuccess(uniqueID, operationSuccess)
                        self.notifyMasterOfPolicyUpdate({ 
                            "username":username,
                            "updateType":op
                        })


                elif (op == "deleteRole"):
                    roleName = operation["roleName"] + "_" + uniqueID if (uniqueRoleNames and operation["roleName"] != BaseRBAC.adminName) else operation["roleName"]
                    if (ignoreDeleteRole):
                        logging.debug("Path " 
                            + uniqueID 
                            + ": skipping deleteRole operation, roleName = " 
                            + roleName
                        ) 
                    else:
                        logging.debug("Path " 
                            + uniqueID 
                            + ": deleteRole, roleName = " 
                            + roleName
                        )
                        self.askMasterToReservePolicy()
                        operationSuccess = self.adapter.deleteRole(
                            roleName = roleName,
                            measure = measure
                        )
                        self.assertSuccess(uniqueID, operationSuccess)
                        self.notifyMasterOfPolicyUpdate({ 
                            "roleName":roleName,
                            "updateType":op
                        })
                        

                elif (op == "deleteResource"):
                    type = operation["type"]
                    resourceName = operation["resourceName"] + "_" + uniqueID if (type == "transient" and uniqueTransientResourceNames) else operation["resourceName"]
                    if (ignoreDeleteResource):
                        logging.debug("Path " 
                            + uniqueID 
                            + ": skipping deleteResource operation, resourceName = " 
                            + resourceName
                        ) 
                    else:
                        logging.debug("Path " 
                            + uniqueID 
                            + ": deleteResource, resourceName = " 
                            + resourceName
                        )
                        self.askMasterToReservePolicy()
                        operationSuccess = self.adapter.deleteResource(
                            resourceName = resourceName,
                            measure = measure
                        )
                        self.assertSuccess(uniqueID, operationSuccess)
                        self.notifyMasterOfPolicyUpdate({ 
                            "resourceName":resourceName,
                            "updateType":op
                        })
                        

                elif (op == "assignUser"):
                    username = operation["username"] + "_" + uniqueID if (uniqueUserNames and operation["username"] != BaseRBAC.adminName) else operation["username"]
                    roleName = operation["roleName"] + "_" + uniqueID if (uniqueRoleNames and operation["roleName"] != BaseRBAC.adminName) else operation["roleName"]
                    if (ignoreAssignUser):
                        logging.debug("Path " 
                            + uniqueID 
                            + ": skipping assignUser operation, username = " 
                            + username
                            + ", roleName = "
                            + roleName
                        ) 
                    else:
                        logging.debug("Path " 
                            + uniqueID 
                            + ": assignUser, username = " 
                            + username
                            + ", roleName = " 
                            + roleName
                        )
                        self.askMasterToReservePolicy()
                        operationSuccess = self.adapter.assignUserToRole(
                            username = username,
                            roleName = roleName,
                            measure = measure
                        )
                        self.assertSuccess(uniqueID, operationSuccess)
                        self.notifyMasterOfPolicyUpdate({ 
                            "username":username,
                            "roleName":roleName,
                            "updateType":op
                        })
                        

                elif (op == "assignPermission"):
                    type = operation["type"]
                    resourceName = operation["resourceName"] + "_" + uniqueID if (type == "transient" and uniqueTransientResourceNames) else operation["resourceName"]
                    roleName = operation["roleName"] + "_" + uniqueID if (uniqueRoleNames and operation["roleName"] != BaseRBAC.adminName) else operation["roleName"]
                    permission = operation["permission"]
                    if (ignoreAssignPermission):
                        logging.debug("Path " 
                            + uniqueID 
                            + ": skipping assignPermission operation, roleName = " 
                            + roleName
                            + ", resourceName = "
                            + resourceName
                        )
                    elif (ignorePersistentAssignRevokePermission and type == "persistent"):
                        logging.debug("Path " 
                            + uniqueID 
                            + ": skipping assignPermission operation on persistent resource, roleName = " 
                            + roleName
                            + ", resourceName = "
                            + resourceName
                        )
                    else:
                        logging.debug("Path " 
                            + uniqueID 
                            + ": assignPermission, roleName = " 
                            + roleName
                            + ", resourceName = " 
                            + resourceName
                            + ", permission = " 
                            + permission
                        )
                        self.askMasterToReservePolicy()
                        operationSuccess = self.adapter.assignPermissionToRole(
                            roleName = roleName,
                            resourceName = resourceName,
                            permission = permission,
                            measure = measure
                        )
                        self.assertSuccess(uniqueID, operationSuccess)
                        self.notifyMasterOfPolicyUpdate({ 
                            "roleName":roleName,
                            "resourceName":resourceName,
                            "permission":permission,
                            "updateType":op
                        })
                        

                elif (op == "revokeUser"):
                    username = operation["username"] + "_" + uniqueID if (uniqueUserNames and operation["username"] != BaseRBAC.adminName) else operation["username"]
                    roleName = operation["roleName"] + "_" + uniqueID if (uniqueRoleNames and operation["roleName"] != BaseRBAC.adminName) else operation["roleName"]
                    if (ignoreRevokeUser):
                        logging.debug("Path " 
                            + uniqueID 
                            + ": skipping revokeUser operation, username = " 
                            + username
                            + ", roleName = "
                            + roleName
                        ) 
                    else:
                        logging.debug("Path " 
                            + uniqueID 
                            + ": revokeUser, username = " 
                            + username
                            + ", roleName = " 
                            + roleName
                        )
                        self.askMasterToReservePolicy()
                        operationSuccess = self.adapter.revokeUserFromRole(
                            username = username,
                            roleName = roleName,
                            measure = measure
                        )
                        self.assertSuccess(uniqueID, operationSuccess)
                        self.notifyMasterOfPolicyUpdate({ 
                            "username":username,
                            "roleName":roleName,
                            "updateType":op
                        })
                        

                elif (op == "revokePermission"):
                    type = operation["type"]
                    resourceName = operation["resourceName"] + "_" + uniqueID if (type == "transient" and uniqueTransientResourceNames) else operation["resourceName"]
                    roleName = operation["roleName"] + "_" + uniqueID if (uniqueRoleNames and operation["roleName"] != BaseRBAC.adminName) else operation["roleName"]
                    permission = operation["permission"]
                    if (ignoreRevokePermission):
                        logging.debug("Path " 
                            + uniqueID 
                            + ": skipping revokePermission operation, roleName = " 
                            + roleName
                            + ", resourceName = "
                            + resourceName
                        ) 
                    elif (ignorePersistentAssignRevokePermission and type == "persistent"):
                        logging.debug("Path " 
                            + uniqueID 
                            + ": skipping revokePermission operation on persistent resource, roleName = " 
                            + roleName
                            + ", resourceName = "
                            + resourceName
                        )
                    else:
                        logging.debug("Path " 
                            + uniqueID 
                            + ": revokePermission, roleName = " 
                            + roleName
                            + ", resourceName = " 
                            + resourceName
                            + ", permission = " 
                            + permission
                        )
                        self.askMasterToReservePolicy()
                        operationSuccess = self.adapter.revokePermissionFromRole(
                            roleName = roleName,
                            resourceName = resourceName,
                            permission = permission,
                            measure = measure
                        )
                        self.assertSuccess(uniqueID, operationSuccess)
                        self.notifyMasterOfPolicyUpdate({ 
                            "roleName":roleName,
                            "resourceName":resourceName,
                            "updateType":op
                        })
                        

                elif (op == "readResource"):
                    type = operation["type"]
                    resourceName = operation["resourceName"] + "_" + uniqueID if (type == "transient" and uniqueTransientResourceNames) else operation["resourceName"]
                    roleName = operation["roleName"] + "_" + uniqueID if (uniqueRoleNames and operation["roleName"] != BaseRBAC.adminName) else operation["roleName"]
                    if (ignoreReadResource):
                        logging.debug("Path " 
                            + uniqueID 
                            + ": skipping readResource operation, resourceName = "
                            + resourceName
                        ) 
                    else:
                        logging.debug("Path " 
                            + uniqueID 
                            + ": readResource, resourceName = " 
                            + resourceName
                            + " as role with roleName = "
                            + roleName
                        )
                        userToUse = self.askMasterToReserveUserBelongingToRole(roleName)
                        resourceContent = self.adapter.readResource(
                            resourceName = resourceName,
                            userToUse = userToUse,
                            assumedRoleName = roleName,
                            measure = measure
                        )
                        self.notifyMasterToReleaseUser(userToUse)
                        if (resourceContent == True or resourceContent == False):
                            logging.debug("Read resource operation returned " + str(resourceContent))
                            self.assertSuccess(uniqueID, resourceContent)


                elif (op == "writeResource"):
                    type = operation["type"]
                    resourceName = operation["resourceName"] + "_" + uniqueID if (type == "transient" and uniqueTransientResourceNames) else operation["resourceName"]
                    roleName = operation["roleName"] + "_" + uniqueID if (uniqueRoleNames and operation["roleName"] != BaseRBAC.adminName) else operation["roleName"]
                    if (ignoreWriteResource):
                        logging.debug("Path " 
                            + uniqueID 
                            + ": skipping writeResource operation, resourceName = "
                            + resourceName
                        ) 
                    else:
                        logging.debug("Path " 
                            + uniqueID 
                            + ": writeResource, resourceName = " 
                            + resourceName
                            + " as role with roleName = "
                            + roleName
                        )
                        resourceContent = getRandomString(
                            sizeInBytes = int(operation["resourceSize"])
                        )
                        userToUse = self.askMasterToReserveUserBelongingToRole(roleName)
                        operationSuccess = self.adapter.writeResource(
                            resourceName = resourceName,
                            userToUse = userToUse,
                            assumedRoleName = roleName,
                            resourceContent = resourceContent,
                            measure = measure
                        )
                        self.notifyMasterToReleaseUser(userToUse)
                        self.assertSuccess(uniqueID, operationSuccess)
                        

        endTime = time.time()
        workflowCompletionTime = (endTime - startTime - self.idlingTime) * 1000

        events.request.fire(
            request_type = "Workflow Execution Time",
            name = uniqueID,
            response_time = workflowCompletionTime, 
            response_length = 0,
            exception=None,
            context={}
        )

        events.request.fire(
            request_type = "Workflow Idling Time",
            name = uniqueID,
            response_time = self.idlingTime * 1000, 
            response_length = 0,
            exception=None,
            context={}
        )

        events.request.fire(
            request_type = "WorkflowCompleted",
            name = uniqueID,
            response_time = 0, 
            response_length = 0,
            exception=None,
            context={}
        )

        # We successfully executed the workflow
        logging.info("Successfully executed workflow " 
            + workflow 
            + ", path with ID "
            + pathID
            + ", repetition of workflow "
            + str(currentRunWorkflow)
            + ", repetition of path "
            + str(currentRunPath)
            + ", completion time "
            + str(workflowCompletionTime)
            + " milliseconds, idling time "
            + str(self.idlingTime * 1000)
            + " milliseconds (unique ID: "
            + uniqueID
            + ")"
        )

        # Reset the idling time
        self.idlingTime = 0
