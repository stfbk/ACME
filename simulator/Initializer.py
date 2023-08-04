#!/usr/bin/python

from adapters.CryptoAC.CryptoACRBAC import CryptoACRBAC
from adapters.OPA.OPARBAC import OPARBAC
from adapters.OPA.OPAWithDMRBAC import OPAWithDMRBAC
from adapters.XACML.XACMLRBAC import XACMLRBAC
from adapters.XACML.XACMLWithDMRBAC import XACMLWithDMRBAC
from random import choice
from string import ascii_lowercase
from io import UnsupportedOperation
from xml.dom.minidom import parse
import names, string, argparse, re, logging, requests, json, random, time, urllib3
import os.path

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

operationFiles = None
flexibleACState = None
    

def generateUsernames(quantity): 
    logging.debug("Generating " + str(quantity) + " usernames")
    usernames = []
    maximumTries = 10000
    currentTries = 0
    while (len(usernames) < quantity and currentTries < maximumTries):
        newUsername = names.get_first_name()
        if (newUsername not in usernames):
            usernames.append(newUsername)
            currentTries = 0
        else:
            currentTries += 1

    if (currentTries == maximumTries):
        logging.error("Could not generate " + str(quantity) + " usernames, generation failed")
        exit(3)
    return usernames
   
def generateRoleNames(quantity): 
    global flexibleACState
    roleNames = []
    if (operationFiles != None):
        logging.info("Generating " + str(quantity) + " role names from operations")
        for operationFile in operationFiles:
            with open(operationFile, "r") as operationFileReader:
                logging.debug("Reading operation file " + operationFile)
                operationFileContent = operationFileReader.read()
                operationFileRoleNames = re.findall('"op":"addRole", "roleName":"(.+?)"', operationFileContent)
                roleNames.extend(set(operationFileRoleNames))
    if (len(roleNames) < quantity):
        if (not flexibleACState):
            raise ValueError("The AC policy state has more roles than the workflows")
        logging.warning("The AC policy state has more roles than the workflows, but flexible AC state was set")
        
        logging.info("Generating " + str(quantity - len(roleNames)) + " role names randomly")
        maximumTries = 10000
        currentTries = 0
        while (len(roleNames) < quantity and currentTries < maximumTries):
            newRoleName = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
            if (newRoleName not in roleNames):
                roleNames.append(newRoleName)
                currentTries = 0
            else:
                currentTries += 1
        if (currentTries == maximumTries):
            logging.error("Could not generate " + str(quantity) + " role names, generation failed")
            exit(3)
    if (len(roleNames) > quantity):
        if (not flexibleACState):
            raise ValueError("The AC policy state has less roles than the workflows")
        logging.warning("The AC policy state has less roles than the workflows, but flexible AC state was set")
        logging.warning("Modifying number of roles to " + str(len(roleNames)))
    return roleNames
        
def generateResourceNames(quantity): 
    resourceNames = []
    if (operationFiles != None):
        logging.info("Generating " + str(quantity) + " resource names from operations")
        for operationFile in operationFiles:
            with open(operationFile, "r") as operationFileReader:
                logging.debug("Reading operation file " + operationFile)
                operationFileContent = operationFileReader.read()
                operationFileResourceNames = re.findall('"vertex":"a-priori", "op":"addResource", "resourceName":"(.+?)", "roleName":".*", "type":"persistent"', operationFileContent)
                resourceNames.extend(set(operationFileResourceNames))
    if (len(resourceNames) < quantity):
        if (not flexibleACState):
            raise ValueError("The AC policy state has more resources than the workflows")
        logging.warning("The AC policy state has more resources than the workflows, but flexible AC state was set")

        logging.info("Generating " + str(quantity - len(resourceNames)) + " resource names randomly")
        maximumTries = 10000
        currentTries = 0
        while (len(resourceNames) < quantity and currentTries < maximumTries):
            newResourceName = "tmp_" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
            if (newResourceName not in resourceNames):
                resourceNames.append(newResourceName)
                currentTries = 0
            else:
                currentTries += 1
        if (currentTries == maximumTries):
            logging.error("Could not generate " + str(quantity) + " resource names, generation failed")
            exit(3)
    if (len(resourceNames) > quantity):
        if (not flexibleACState):
            raise ValueError("The AC policy state has less resources than the workflows")
        logging.warning("The AC policy state has less resources than the workflows, but flexible AC state was set")
        logging.warning("Modifying number of resources to " + str(len(resourceNames)))
    return resourceNames



#        ____      _ __  _       ___                
#       /  _/___  (_) /_(_)___ _/ (_)___  ___  _____
#       / // __ \/ / __/ / __ `/ / /_  / / _ \/ ___/
#     _/ // / / / / /_/ / /_/ / / / / /_/  __/ /    
#    /___/_/ /_/_/\__/_/\__,_/_/_/ /___/\___/_/                                                   
#                                                             
# The steps are:
# 1. parse the command line arguments; 
# 2. generate users, roles and resources;
# 3. generate UR assignments;
# 4. generate PA assignments;
# 5. check constraints.




















# ===== ===== ===== ===== ===== ===== start 1 ===== ===== ===== ===== ===== ===== 
# Parse the command line arguments
parser = argparse.ArgumentParser(description='Initializer')

parser.add_argument(
    "state", 
    type=str, 
    help="The path to the .json file containing the state to initialize the adapter (available are 'test' (test purposes only), 'domino', 'emea', 'firewall1', 'firewall2', 'healthcare' and 'university')"
)

parser.add_argument(
    "adapter", 
    type=str,
    help="The adapter to use among 'CryptoAC', 'OPA', 'OPAWithDM', 'XACML' and 'XACMLWithDM'. Please refer to the implementation of each adapter for more details. Note that other adapters can be easily implemented (follow the instructions in the 'BaseRBAC' class)."
)

parser.add_argument(
    "host", 
    type=str,
    help="The ULR of the adapter"
)

parser.add_argument(
    "--seed", 
    type=str, 
    help="The seed for random generation (default is '1')"
)

parser.add_argument(
    "--logLevel", 
    type=str,
    help="Log level among 'DEBUG', 'INFO', 'WARNING' (default), 'ERROR' and 'CRITICAL'"
)

parser.add_argument(
    "--logFile", 
    type=str,
    help="File (path) where to log (default log to console)"
)

parser.add_argument(
    "--adminName", 
    type=str,
    help="In case one or more resources are expected to already exist before executing the workflow (i.e., they are not created by any activity but are assumed to be provided as an external input), we treat them as if the administrator was creating such resources. For this reason, please provide the username of the administrator (default is 'admin')"
)

parser.add_argument(
    '--doInitialize', 
    action='store_true',
    help="Whether the adapter needs to be initialized. In other words, if this option is specified, the 'initialize' method of the adapter (of each Locust instance) will be invoked. Usually, this option is specified when invoking the initializer (thus, here)."
)

parser.add_argument(
    '--operations', 
    type=str,
    help="Path to one or more .json files separated by a ';' containing list of AC operations from which take role and resource names (if not given, role and resource names will be generated randomly). For instance, 'path/to/file/1.json;path/to/file_2.json'. If the operations do not contain enough names, the remaining will be generated randomly. If the operations contain too many names, the program will either exit with an error code or (if 'flexibleACState' was specified) modify the access control policy state accordingly"
)

parser.add_argument(
    '--flexibleACState', 
    action='store_true',
    help="Whether the access control policy state can be modified to adapt to the given operations (see the 'operations' option for more details)"
)


args = parser.parse_args()

state = args.state
host = args.host
doInitialize = args.doInitialize
flexibleACState = args.flexibleACState

logLevel = "WARNING" if not args.logLevel else args.logLevel
numeric_level = getattr(logging, logLevel.upper(), None)
if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: %s' % logLevel)
if not args.logFile:
    logging.basicConfig(level=numeric_level)
else:
    logging.basicConfig(
        filename=args.logFile,
        filemode='w',
        format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
        datefmt='%H:%M:%S',
        level=numeric_level
    )

logging.info(
    """
        ____      _ __  _       ___                
       /  _/___  (_) /_(_)___ _/ (_)___  ___  _____
       / // __ \/ / __/ / __ `/ / /_  / / _ \/ ___/
     _/ // / / / / /_/ / /_/ / / / / /_/  __/ /    
    /___/_/ /_/_/\__/_/\__,_/_/_/ /___/\___/_/     
                                               
    """
)

adapterToUse = args.adapter
if (adapterToUse == "CryptoAC"):
    logging.info("Chose CryptoAC as adapter")
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

seed = args.seed
if args.seed:
    logging.info("Seed is " + str(seed))
    random.seed(int(seed))
else:
    seed = 1

adminName = "admin" if not args.adminName else args.adminName

operations = args.operations
if args.operations:
    operationFiles = operations.split(";")
    logging.info("Using operations for role and resource names: " + ", ".join(operationFiles))

for operationFile in operationFiles:
    if (not os.path.isfile(operationFile)):
        logging.error("File " + operationFile + " not found")
        exit(1)


with open(state, "r") as fileReader:
    logging.info("Reading state " + state)
    stateJson = json.loads(fileReader.read())
    policy_U = stateJson["U"]
    policy_R = stateJson["R"]
    policy_P = stateJson["P"]
    policy_UR = stateJson["UR"]
    policy_PA = stateJson["PA"]
    policy_roles_user = stateJson["roles/user"]
    policy_roles_user_max = policy_roles_user["max"]
    policy_roles_user_min = policy_roles_user["min"]
    policy_users_role = stateJson["users/role"]
    policy_users_role_max = policy_users_role["max"]
    policy_users_role_min = policy_users_role["min"]
    policy_permissions_role = stateJson["permissions/role"]
    policy_permissions_role_max = policy_permissions_role["max"]
    policy_permissions_role_min = policy_permissions_role["min"]
    policy_roles_permission = stateJson["roles/permission"]
    policy_roles_permission_max = policy_roles_permission["max"]
    policy_roles_permission_min = policy_roles_permission["min"]
    logging.info("policy_U: " + str(policy_U))
    logging.info("policy_R: " + str(policy_R))
    logging.info("policy_P: " + str(policy_P))
    logging.info("policy_UR: " + str(policy_UR))
    logging.info("policy_PA: " + str(policy_PA))
    logging.info("policy_roles_user_max: " + str(policy_roles_user_max))
    logging.info("policy_roles_user_min: " + str(policy_roles_user_min))
    logging.info("policy_users_role_max: " + str(policy_users_role_max))
    logging.info("policy_users_role_min: " + str(policy_users_role_min))
    logging.info("policy_permissions_role_max: " + str(policy_permissions_role_max))
    logging.info("policy_permissions_role_min: " + str(policy_permissions_role_min))
    logging.info("policy_roles_permission_max: " + str(policy_roles_permission_max))
    logging.info("policy_roles_permission_min: " + str(policy_roles_permission_min))

logging.info("Initializing the adapter " + adapterToUse +  " with policy state " + state + " (seed = '" + seed + "')")
logging.info("===== ===== ===== ===== ===== ===== end 1 ===== ===== ===== ===== ===== =====")
# ===== ===== ===== ===== ===== ===== end 1 ===== ===== ===== ===== ===== ===== 




















# ===== ===== ===== ===== ===== ===== start 2 ===== ===== ===== ===== ===== ===== 
# Generate users, roles and resources
logging.info("===== ===== ===== ===== ===== ===== start 2 ===== ===== ===== ===== ===== =====")

# Create the adapter
if (adapterToUse == "CryptoAC"):
    adapter = CryptoACRBAC(
        host = host, 
        logging = logging,
        username = CryptoACRBAC.adminName,
        doInitialize = doInitialize
    )
elif (adapterToUse == "OPA"):
    adapter = OPARBAC(
        host = host, 
        logging = logging,
        username = OPARBAC.adminName,
        doInitialize = doInitialize
    )
elif (adapterToUse == "OPAWithDM"):
    adapter = OPAWithDMRBAC(
        host = host, 
        logging = logging,
        username = OPAWithDMRBAC.adminName,
        doInitialize = doInitialize
    )
elif (adapterToUse == "XACML"):
    adapter = XACMLRBAC(
        host = host, 
        logging = logging,
        username = XACMLRBAC.adminName,
        doInitialize = doInitialize
    )
elif (adapterToUse == "XACMLWithDM"):
    adapter = XACMLWithDMRBAC(
        host = host, 
        logging = logging,
        username = XACMLWithDMRBAC.adminName,
        doInitialize = doInitialize
    )

# Do not verity TLS certificates
client = requests.Session()
client.verify = False
adapter.setClient(client)
adapter.on_start()

# Generate unique usernames and create users
policy_roles_by_user = {}
usernames = generateUsernames(policy_U)
for x in range(policy_U):
    username = usernames[x]
    logging.info("Adding user " + username)
    assert(adapter.addUser(username, measure = False))
    policy_roles_by_user[username] = []

# Generate unique role names and create roles
policy_users_by_role = {}
policy_resources_by_role = {}
roleNames = generateRoleNames(policy_R)
policy_R = len(roleNames)
for x in range(policy_R):
    roleName = roleNames[x]
    logging.info("Adding role " + roleName)
    assert(adapter.addRole(roleName, measure = False))
    policy_users_by_role[roleName] = []
    policy_resources_by_role[roleName] = []

# Generate unique resource names and create resources
policy_roles_by_resource = {}
resourceNames = generateResourceNames(policy_P)
policy_P = len(resourceNames)
for x in range(policy_P):
    resourceName = resourceNames[x]
    logging.info("Adding resource " + resourceName)
    assert(not (adapter.addResource(
        resourceName = resourceName, 
        assumedRoleName = adminName,
        userToUse = adminName,
        resourceContent = ''.join([choice(ascii_lowercase) for _ in range(1024)]), 
        measure = False
    ) == False))
    policy_roles_by_resource[resourceName] = []
logging.info("===== ===== ===== ===== ===== ===== end 2 ===== ===== ===== ===== ===== =====")
# ===== ===== ===== ===== ===== ===== end 2 ===== ===== ===== ===== ===== ===== 




















# ===== ===== ===== ===== ===== ===== start 3 ===== ===== ===== ===== ===== ===== 
# Generate UR assignments
logging.info("===== ===== ===== ===== ===== ===== start 3 ===== ===== ===== ===== ===== =====")
numberOfGeneratedURAssignments = 0

# First, distribute minimum number of UR assignments to users
logging.info("Distributing minimum number of UR assignments to users")
for username in usernames:

    logging.info("Ensuring that user " + username + " has minimum number of UR assignments (" + str(policy_roles_user_min) + ")")

    # Get minimum number of random role names
    randomRoleNames = random.sample(roleNames, policy_roles_user_min)

    # Check that all role names we picked have not already reached 
    # the maximum number of assignable users (policy_users_role_max)
    maximumSatisfied = False
    rolesIndex = 0
    while (not maximumSatisfied):
        maximumSatisfied = True
        for randomRoleName in randomRoleNames:
            if (len(policy_users_by_role[randomRoleName]) == policy_users_role_max):
                logging.debug("Role " + randomRoleName + " has already reached maximum UR assignments")
                maximumSatisfied = False
                randomRoleNames.remove(randomRoleName)
                foundAnotherRole = False
                while (not foundAnotherRole):
                    replacementRoleName = roleNames[rolesIndex]
                    if (len(policy_users_by_role[replacementRoleName]) < policy_users_role_max
                       and 
                       replacementRoleName not in randomRoleNames
                    ):
                        logging.debug("Replacing with role " + replacementRoleName)
                        randomRoleNames.append(replacementRoleName)
                        foundAnotherRole = True
                    rolesIndex = rolesIndex + 1
                    if (rolesIndex >= policy_R):
                        logging.error("Could not find another role, generation failed")
                        exit(1)
                
    # We can now assign the minimum number of roles to the current user 
    for x in range(policy_roles_user_min):
        randomRoleName = randomRoleNames[x]
        logging.info("Assigning role " + randomRoleName + " to user " + username)
        assert(adapter.assignUserToRole(
            username = username, 
            roleName = randomRoleName,
            measure = False
        ))
        policy_users_by_role[randomRoleName].append(username)
        policy_roles_by_user[username].append(randomRoleName)
        numberOfGeneratedURAssignments += 1


# Second, distribute minimum number of UR assignments to roles
# Note that we should not consider users already assigned to current roles
logging.info("Distributing minimum number of UR assignments to roles")
for roleName in roleNames:

    logging.info("Ensuring that role " + roleName + " has minimum number of UR assignments (" + str(policy_users_role_min) + ")")

    usersToAssignToTheRole = policy_users_role_min - len(policy_users_by_role[roleName])
    if (usersToAssignToTheRole > 0):

        # Get minimum number of random usernames
        usersNotAlreadyAssignedToRole = list(set(usernames) - set(policy_users_by_role[roleName]))  
        if (len(usersNotAlreadyAssignedToRole) < usersToAssignToTheRole):
            logging.error(
                "Impossible generation; we should assign "
                + str(usersToAssignToTheRole)
                + " users to role " 
                + roleName
                + ", but only "
                + str(len(usersNotAlreadyAssignedToRole))
                + " users remain"
            )
            exit(4)
        else:
            logging.info("Choosing random usernames from list of size " + str(len(usersNotAlreadyAssignedToRole)))
        randomUsernames = random.sample(usersNotAlreadyAssignedToRole, usersToAssignToTheRole)

        # Check that all usernames we picked have not already reached 
        # the maximum number of assignable roles (policy_roles_user_max)
        maximumSatisfied = False
        usersIndex = 0
        while (not maximumSatisfied):
            maximumSatisfied = True
            for randomUsername in randomUsernames:
                if (len(policy_roles_by_user[randomUsername]) == policy_roles_user_max):
                    logging.debug("User " + randomUsername + " has already reached maximum UR assignments")
                    maximumSatisfied = False
                    randomUsernames.remove(randomUsername)
                    foundAnotherUser = False
                    while (not foundAnotherUser):
                        replacementUsername = usersNotAlreadyAssignedToRole[usersIndex]
                        if (len(policy_roles_by_user[replacementUsername]) < policy_roles_user_max
                            and 
                            replacementUsername not in randomUsernames
                        ):
                            logging.debug("Replacing with user " + replacementUsername)
                            randomUsernames.append(replacementUsername)
                            foundAnotherUser = True
                        usersIndex = usersIndex + 1
                        if (usersIndex >= len(usersNotAlreadyAssignedToRole)):
                            logging.error("Could not find another user, generation failed")
                            exit(2)
                    
        # We can now assign the minimum number of users to the current role
        for x in range(usersToAssignToTheRole):
            randomUsername = randomUsernames[x]
            logging.info("Assigning role " + roleName + " to user " + randomUsername)
            assert(adapter.assignUserToRole(
                username = randomUsername, 
                roleName = roleName,
                measure = False
            ))
            policy_users_by_role[roleName].append(randomUsername)
            policy_roles_by_user[randomUsername].append(roleName)
            numberOfGeneratedURAssignments += 1
    
    else:
        logging.info("Role " + roleName + " has already reached minimum UR assignments")


# Generate the remaining UR assignments
maximumTries = 10000
currentTries = 0
logging.info("Generating remaining UR assignments")
while (numberOfGeneratedURAssignments < policy_UR and currentTries < maximumTries):
    username = random.choice(usernames)
    roleName = random.choice(roleNames)
    if (
        len(policy_roles_by_user[username]) < policy_roles_user_max
        and 
        len(policy_users_by_role[roleName]) < policy_users_role_max
        and
        username not in policy_users_by_role[roleName]
    ):
        logging.info("Assigning role " + roleName + " to user " + username)
        assert(adapter.assignUserToRole(
            username = username, 
            roleName = roleName,
            measure = False
        ))
        policy_users_by_role[roleName].append(username)
        policy_roles_by_user[username].append(roleName)
        numberOfGeneratedURAssignments += 1
        currentTries = 0
    else:
        currentTries += 1
if (numberOfGeneratedURAssignments < policy_UR and currentTries == maximumTries):
    logging.error(
        "Could not reach the number of UR assignments (current UR assignments number is "
        + str(numberOfGeneratedURAssignments)
        + ", required is " 
        + str(policy_UR)
        + "), generation failed"
    )
    exit(2)

logging.info("===== ===== ===== ===== ===== ===== end 3 ===== ===== ===== ===== ===== =====")
# ===== ===== ===== ===== ===== ===== end 3 ===== ===== ===== ===== ===== ===== 


















# ===== ===== ===== ===== ===== ===== start 4 ===== ===== ===== ===== ===== ===== 
# Generate PA assignments
logging.info("===== ===== ===== ===== ===== ===== start 4 ===== ===== ===== ===== ===== =====")
numberOfGeneratedPAAssignments = 0

# Derive PA assignments from AC operations
tmpREADPermissionsToAssignToRole = {}
tmpWRITEPermissionsToAssignToRole = {}
for operationFile in operationFiles:
    with open(operationFile, "r") as operationFileReader:
        logging.debug("Reading operation file " + operationFile)
        operationFileContent = operationFileReader.read()
        operationFilePersistentResourceNames = set(re.findall('"vertex":"a-priori", "op":"addResource", "resourceName":"(.+?)", "roleName":".*", "type":"persistent"', operationFileContent))
        for operationFilePersistentResourceName in operationFilePersistentResourceNames:
           operationFileRolesToAssignPermission = set(re.findall('"op":"assignPermission", "resourceName":"' + operationFilePersistentResourceName + '", "roleName":"(.+?)"', operationFileContent))
           for operationFileRoleToAssignPermission in operationFileRolesToAssignPermission:
                operationFilePermissionsToAssign = set(re.findall('"op":"assignPermission", "resourceName":"' + operationFilePersistentResourceName + '", "roleName":"' + operationFileRoleToAssignPermission + '", "permission":"(.+?)"', operationFileContent))
                for operationFilePermissionToAssign  in operationFilePermissionsToAssign:
                    logging.info("We should assign permission " + operationFilePermissionToAssign + " over resource " + operationFilePersistentResourceName + " to role " + operationFileRoleToAssignPermission)
                    if (operationFileRoleToAssignPermission not in tmpREADPermissionsToAssignToRole):
                        tmpREADPermissionsToAssignToRole[operationFileRoleToAssignPermission] = set()
                        tmpWRITEPermissionsToAssignToRole[operationFileRoleToAssignPermission] = set()
                    if ("READ" in operationFilePermissionToAssign):
                        tmpREADPermissionsToAssignToRole[operationFileRoleToAssignPermission].add(operationFilePersistentResourceName)
                    if ("WRITE" in operationFilePermissionToAssign):
                        tmpWRITEPermissionsToAssignToRole[operationFileRoleToAssignPermission].add(operationFilePersistentResourceName)

for roleName in tmpREADPermissionsToAssignToRole:
    for resourceName in tmpREADPermissionsToAssignToRole[roleName]:
        logging.info("Therefore, we assign permission READ over resource " + resourceName + " to role " + roleName)
        assert(adapter.assignPermissionToRole(
            roleName = roleName, 
            resourceName = resourceName,
            permission = "READ",
            measure = False
        ))
        policy_roles_by_resource[resourceName].append(roleName)
        policy_resources_by_role[roleName].append(resourceName)
        numberOfGeneratedPAAssignments += 1

for roleName in tmpWRITEPermissionsToAssignToRole:
    for resourceName in tmpWRITEPermissionsToAssignToRole[roleName]:
        logging.info("Therefore, we assign permission WRITE over resource " + resourceName + " to role " + roleName)
        assert(adapter.assignPermissionToRole(
            roleName = roleName, 
            resourceName = resourceName,
            permission = "WRITE",
            measure = False
        ))
        policy_roles_by_resource[resourceName].append(roleName)
        policy_resources_by_role[roleName].append(resourceName)
        numberOfGeneratedPAAssignments += 1




# First, distribute minimum number of PA assignments to roles
logging.info("Distributing minimum number of PA assignments to roles")
for roleName in roleNames:

    logging.info("Ensuring that role " + roleName + " has minimum number of PA assignments (" + str(policy_permissions_role_min) + ")")

    # Get minimum number of random resource names
    randomResourceNames = random.sample(resourceNames, policy_permissions_role_min)

    # Check that all resource names we picked have not already reached 
    # the maximum number of assignable roles (policy_roles_permission_max)
    maximumSatisfied = False
    resourcesIndex = 0
    while (not maximumSatisfied):
        maximumSatisfied = True
        for randomResourceName in randomResourceNames:
            if (len(policy_roles_by_resource[randomResourceName]) == policy_roles_permission_max or randomResourceName in policy_resources_by_role[roleName]):
                logging.debug("Resource " + randomResourceName + " has already reached maximum PA assignments or is already assigned to role " + roleName)
                maximumSatisfied = False
                randomResourceNames.remove(randomResourceName)
                foundAnotherResource = False
                while (not foundAnotherResource):
                    replacementResourceName = resourceNames[resourcesIndex]
                    if (len(policy_roles_by_resource[replacementResourceName]) < policy_roles_permission_max
                       and 
                       replacementResourceName not in randomResourceNames
                       and 
                       (replacementResourceName not in policy_resources_by_role[roleName])
                    ):
                        logging.debug("Replacing with resource " + replacementResourceName)
                        randomResourceNames.append(replacementResourceName)
                        foundAnotherResource = True
                    resourcesIndex = resourcesIndex + 1
                    if (resourcesIndex >= policy_P):
                        logging.error("Could not find another resource, generation failed")
                        exit(1)
                
    # We can now assign the minimum number of resources to the current role
    for x in range(policy_permissions_role_min):
        randomResourceName = randomResourceNames[x]
        logging.info("Assigning resource " + randomResourceName + " to role " + roleName)
        assert(adapter.assignPermissionToRole(
            roleName = roleName, 
            resourceName = randomResourceName,
            permission = "READ",
            measure = False
        ))
        policy_roles_by_resource[randomResourceName].append(roleName)
        policy_resources_by_role[roleName].append(randomResourceName)
        numberOfGeneratedPAAssignments += 1


# Second, distribute minimum number of PA assignments to resources
logging.info("Distributing minimum number of PA assignments to resources")
for resourceName in resourceNames:

    logging.info("Ensuring that resource " + resourceName + " has minimum number of PA assignments (" + str(policy_roles_permission_min) + ")")

    rolesToAssignToTheResource = policy_roles_permission_min - len(policy_roles_by_resource[resourceName])
    if (rolesToAssignToTheResource > 0):

        # Get minimum number of random role names
        rolesNotAlreadyAssignedToResource = list(set(roleNames) - set(policy_roles_by_resource[resourceName]))  
        if (len(rolesNotAlreadyAssignedToResource) < rolesToAssignToTheResource):
            logging.error(
                "Impossible generation; we should assign "
                + str(rolesToAssignToTheResource)
                + " roles to resource " 
                + resourceName
                + ", but only "
                + str(len(rolesNotAlreadyAssignedToResource))
                + " roles remain"
            )
            exit(5)
        else:
            logging.info("Choosing random role names from list of size " + str(len(rolesNotAlreadyAssignedToResource)))
        randomRoleNames = random.sample(rolesNotAlreadyAssignedToResource, rolesToAssignToTheResource)

        # Check that all role names we picked have not already reached 
        # the maximum number of assignable permissions (policy_permissions_role_max)
        maximumSatisfied = False
        rolesIndex = 0
        while (not maximumSatisfied):
            maximumSatisfied = True
            for randomRoleName in randomRoleNames:
                if (len(policy_resources_by_role[randomRoleName]) == policy_permissions_role_max or randomRoleName in policy_roles_by_resource[resourceName]):
                    logging.debug("Role " + randomRoleName + " has already reached maximum PA assignments or is already assigned to resource " + resourceName)
                    maximumSatisfied = False
                    randomRoleNames.remove(randomRoleName)
                    foundAnotherRole = False
                    while (not foundAnotherRole):
                        replacementRoleName = roleNames[rolesIndex]
                        if (len(policy_resources_by_role[replacementRoleName]) < policy_permissions_role_max
                            and 
                            replacementRoleName not in randomRoleNames
                            and 
                            (replacementRoleName not in policy_roles_by_resource[resourceName])
                        ):
                            logging.debug("Replacing with role " + replacementRoleName)
                            randomRoleNames.append(replacementRoleName)
                            foundAnotherRole = True
                        rolesIndex = rolesIndex + 1
                        if (rolesIndex >= policy_R):
                            logging.error("Could not find another role, generation failed")
                            exit(2)
                    
        # We can now assign the minimum number of roles to the current resource
        for x in range(rolesToAssignToTheResource):
            randomRoleName = randomRoleNames[x]
            logging.info("Assigning resource " + resourceName + " to role " + randomRoleName)
            assert(adapter.assignPermissionToRole(
                roleName = randomRoleName, 
                resourceName = resourceName,
                permission = "READ",
                measure = False
            ))
            policy_roles_by_resource[resourceName].append(randomRoleName)
            policy_resources_by_role[randomRoleName].append(resourceName)
            numberOfGeneratedPAAssignments += 1
    
    else:
        logging.info("Resource " + resourceName + " has already reached minimum PA assignments")


# Generate the remaining PA assignments
maximumTries = 10000
currentTries = 0
logging.info("Generating remaining PA assignments")
while (numberOfGeneratedPAAssignments < policy_PA and currentTries < maximumTries):
    roleName = random.choice(roleNames)
    resourceName = random.choice(resourceNames)
    if (
        len(policy_resources_by_role[roleName]) < policy_permissions_role_max
        and 
        len(policy_roles_by_resource[resourceName]) < policy_roles_permission_max
        and
        resourceName not in policy_resources_by_role[roleName]
    ):
        logging.info("Assigning resource " + resourceName + " to role " + roleName)
        assert(adapter.assignPermissionToRole(
            roleName = roleName, 
            resourceName = resourceName,
            permission = "READ",
            measure = False
        ))
        policy_roles_by_resource[resourceName].append(roleName)
        policy_resources_by_role[roleName].append(resourceName)
        numberOfGeneratedPAAssignments += 1
        currentTries = 0
    else:
        currentTries += 1
if (numberOfGeneratedPAAssignments < policy_PA and currentTries == maximumTries):
    logging.error(
        "Could not reach the number of PA assignments (current PA assignments number is "
        + str(numberOfGeneratedPAAssignments)
        + ", required is " 
        + str(policy_PA)
        + "), generation failed"
    )
    exit(2)

logging.info("===== ===== ===== ===== ===== ===== end 4 ===== ===== ===== ===== ===== =====")
# ===== ===== ===== ===== ===== ===== end 4 ===== ===== ===== ===== ===== ===== 




















# ===== ===== ===== ===== ===== ===== start 5 ===== ===== ===== ===== ===== ===== 
# Check constraints
logging.info("===== ===== ===== ===== ===== ===== start 5 ===== ===== ===== ===== ===== =====")

for resource in policy_roles_by_resource:
    rolesByResource = len(policy_roles_by_resource[resource])
    if (rolesByResource < policy_roles_permission_min
        or 
        rolesByResource > policy_roles_permission_max
    ):
        logging.error("Policy roles by resource " + resource + " exceeds constraints (min " + policy_roles_permission_min + ", actual " + rolesByResource + ", max " + policy_roles_permission_max + ")")

for role in policy_resources_by_role:
    resourcesByRole = len(policy_resources_by_role[role])
    if (resourcesByRole < policy_permissions_role_min
        or 
        resourcesByRole > policy_permissions_role_max
    ):
        logging.error("Policy resources by role " + role + " exceeds constraints (min " + policy_permissions_role_min + ", actual " + resourcesByRole + ", max " + policy_permissions_role_max + ")")

for role in policy_users_by_role:
    usersByRole = len(policy_users_by_role[role])
    if (usersByRole < policy_users_role_min
        or 
        usersByRole > policy_users_role_max
    ):
        logging.error("Policy roles by role " + role + " exceeds constraints (min " + policy_users_role_min + ", actual " + usersByRole + ", max " + policy_users_role_max + ")")

logging.info("Constraints checks")
for user in policy_roles_by_user:
    rolesByUser = len(policy_roles_by_user[user])
    if (rolesByUser < policy_roles_user_min 
        or 
        rolesByUser > policy_roles_user_max
    ):
        logging.error("Policy roles by user " + user + " exceeds constraints (min " + policy_roles_user_min + ", actual " + rolesByUser + ", max " + policy_roles_user_max + ")")


adapter.on_stop()

logging.info("===== ===== ===== ===== ===== ===== end 5 ===== ===== ===== ===== ===== =====")
# ===== ===== ===== ===== ===== ===== end 5 ===== ===== ===== ===== ===== ===== 
