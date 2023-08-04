from BaseRBAC import BaseRBAC
import xml.etree.ElementTree as et

# Adapter for XACML (no file storage)
class XACMLRBAC(BaseRBAC):

    # The file containing the XML data
    # to create a domain in the XACML server
    domainRBAC = "./simulator/adapters/XACML/domain_cryptoac.xml"

    # The file containing the XML properties
    # for the PRP in the XACML server
    propertiesPRP = "./simulator/adapters/XACML/properties_PRP.xml"

    # The file containing the admin rule enablement
    # policy set to initialize the XACML server
    adminREPSRBAC = "./simulator/adapters/XACML/admin_REPS.xml"

    # The file containing the admin permission
    # policy set to initialize the XACML server
    adminPPSRBAC = "./simulator/adapters/XACML/admin_PPS.xml"

    # The file containing the admin role
    # policy set to initialize the XACML server
    adminRPSRBAC = "./simulator/adapters/XACML/admin_RPS.xml"

    # The file containing the CryptoAC root
    # policy set to initialize the XACML server
    adminROOTRBAC = "./simulator/adapters/XACML/admin_ROOT.xml"

    # The ID of the CryptoAC domain
    domainCryptoACID = ""


    def on_start(self):
        if (not (self.doInitialize and not BaseRBAC.initialized)):
            assert(self._getCryptoACDomainID(self.cloneClientWithCookies()))
        super().on_start()


    def initialize(self, measure, alternativeInitializationData = None):
        clientToUse = self.client if (measure) else self.clientNotLogged
        self.initialized = True
        return (
            self._createDomain(clientToUse) and
            self._setPRPProperties(clientToUse) and
            self._addOrUpdatePolicySetFromFile(clientToUse, self.adminREPSRBAC) and
            self._addOrUpdatePolicySetFromFile(clientToUse, self.adminPPSRBAC) and
            self._addOrUpdatePolicySetFromFile(clientToUse, self.adminRPSRBAC) and
            self._addOrUpdatePolicySetFromFile(clientToUse, self.adminROOTRBAC) and
            self._settingTheRootPolicySet(clientToUse)
        )


    def _apiLogin(self, clientToUse, username):
        return True


    def _apiLogout(self, clientToUse):
        return True


    def _apiAddUser(self, clientToUse, username):
        return True


    def _apiAddRole(self, clientToUse, roleName):
        rootPolicy = self._getRootPolicySet(clientToUse)
        if (rootPolicy == False):
            return False

        rolePPS = """
        <PolicySet
            xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xsi:schemaLocation="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17 xacml-core-v3-schema-wd-17.xsd"
            PolicySetId="PPS:role:{0}"
            Version="1.0"
            PolicyCombiningAlgId="urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:permit-overrides">
            <Target/>
            <Policy
                PolicyId="Permissions:for:the:role:{0}"
                Version="1.0"
                RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:permit-overrides">
                <Target/>
            </Policy>
        </PolicySet>
        """.format(roleName)
        if (self._addOrUpdatePolicySet(clientToUse, rolePPS) == False):
            return False

        roleREPS = """
        <PolicySet
            xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xsi:schemaLocation="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17 xacml-core-v3-schema-wd-17.xsd"
            PolicySetId="REPS:role:{0}"
            Version="1.0"
            PolicyCombiningAlgId="urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:permit-overrides">
            <Target/>
            <Policy
                xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                xsi:schemaLocation="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17 xacmlcore-v3-schema-wd-17.xsd"
                PolicyId="Assignment:Policy:{0}"
                Version="1.0"
                RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:permit-overrides">
                <Target/>

                <Rule RuleId="{0}:role:requirements" Effect="Permit">
                    <Target>
                        <AnyOf>

                            <!-- one line for each user -->
                            <AllOf>
                                <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
                                    <AttributeValue
                                        DataType="http://www.w3.org/2001/XMLSchema#string">{1}</AttributeValue>
                                    <AttributeDesignator
                                    MustBePresent="false"
                                    Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
                                    AttributeId="urn:oasis:names:tc:xacml:1.0:subject:subject-id"
                                    DataType="http://www.w3.org/2001/XMLSchema#string"/>
                                </Match>
                            </AllOf>

                        </AnyOf>
                        <AnyOf>
                            <AllOf>
                                <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
                                    <AttributeValue
                                        DataType="http://www.w3.org/2001/XMLSchema#string">{0}</AttributeValue>
                                    <AttributeDesignator
                                        MustBePresent="false"
                                        Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource"
                                        AttributeId="urn:oasis:names:tc:xacml:2.0:subject:role"
                                        DataType="http://www.w3.org/2001/XMLSchema#string"/>
                                </Match>
                            </AllOf>
                        </AnyOf>
                        <AnyOf>
                            <AllOf>
                                <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
                                    <AttributeValue
                                        DataType="http://www.w3.org/2001/XMLSchema#string">urn:oasis:names:tc:xacml:2.0:actions:enableRole</AttributeValue>
                                    <AttributeDesignator
                                        MustBePresent="false"
                                        Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action"
                                        AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id"
                                        DataType="http://www.w3.org/2001/XMLSchema#string"/>
                                </Match>
                            </AllOf>
                        </AnyOf>
                    </Target>
                </Rule>
            </Policy>
        </PolicySet>
        """.format(roleName, self.adminName)
        if (self._addOrUpdatePolicySet(clientToUse, roleREPS) == False):
            return False

        roleRPS = """
        <PolicySet
                xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                xsi:schemaLocation="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17 xacml-core-v3-schema-wd-17.xsd"
                PolicySetId="RPS:role:{0}"
                Version="1.0"
                PolicyCombiningAlgId="urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:permit-overrides">
            <Target>
                <AnyOf>
                    <AllOf>
                        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
                            <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">{0}</AttributeValue>
                            <AttributeDesignator MustBePresent="false"
                                                Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
                                                AttributeId="urn:oasis:names:tc:xacml:2.0:subject:role"
                                                DataType="http://www.w3.org/2001/XMLSchema#string"/>
                        </Match>
                    </AllOf>
                </AnyOf>
            </Target>
            <PolicySetIdReference>PPS:role:{0}</PolicySetIdReference>
        </PolicySet>
        """.format(roleName)
        if (self._addOrUpdatePolicySet(clientToUse, roleRPS) == False):
            return False

        et.SubElement(
            rootPolicy,
            "{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}PolicySetIdReference"
        ).text = "RPS:role:" + roleName
        et.SubElement(
            rootPolicy,
            "{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}PolicySetIdReference"
        ).text = "REPS:role:" + roleName
        rootPolicy.attrib['Version'] = self._updatePolicyVersionNumber(rootPolicy.attrib['Version'])

        return self._addOrUpdatePolicySet(clientToUse, et.tostring(rootPolicy))


    def _apiAddResource(self, clientToUse, userToUse, resourceName, assumedRoleName, resourceContent):
        return True


    def _apiDeleteUser(self, clientToUse, username):
        return self._revokeUserFromRoleWildcard(
            clientToUse=clientToUse,
            username=username
        )


    def _apiDeleteRole(self, clientToUse, roleName):

        rootPolicy = self._getRootPolicySet(clientToUse)
        if (rootPolicy == False):
            return False

        self.logging.info("Update the root policy removing the RPS and REPS of " + roleName)

        policySetsToRemove = []
        for policySetIdReference in rootPolicy.iter(tag="{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}PolicySetIdReference"):
            if (roleName == policySetIdReference.text.split(':')[2]):
                policySetsToRemove.append(policySetIdReference)
        for policySetToRemove in policySetsToRemove:
            rootPolicy.remove(policySetToRemove)

        rootPolicy.attrib['Version'] = self._updatePolicyVersionNumber(rootPolicy.attrib['Version'])

        if (self._addOrUpdatePolicySet(clientToUse, et.tostring(rootPolicy)) == False):
            return False

        if (self._deletePolicySetByID(clientToUse, "RPS:role:" + roleName) == False):
            return False

        if (self._deletePolicySetByID(clientToUse, "REPS:role:" + roleName) == False):
            return False

        if (self._deletePolicySetByID(clientToUse, "PPS:role:" + roleName) == False):
            return False


    def _apiDeleteResource(self, clientToUse, resourceName):
        return self._revokePermissionFromRoleWildcard(
            clientToUse=clientToUse,
            resourceName=resourceName
        )


    def _apiAssignUserToRole(self, clientToUse, username, roleName):
        
        roleREPSString = self._getREPSByRole(clientToUse, roleName)
        if (roleREPSString == False):
            return False
        roleREPS = et.fromstring(roleREPSString)

        anyOfs = roleREPS.find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Policy').find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Rule').find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Target').find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}AnyOf')
        anyOfs.insert(
            1,
            et.fromstring("""
                <myns:AllOf
                    xmlns:myns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17">
                    <myns:Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
                        <myns:AttributeValue
                            DataType="http://www.w3.org/2001/XMLSchema#string">{0}</myns:AttributeValue>
                        <myns:AttributeDesignator
                        MustBePresent="false"
                        Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
                        AttributeId="urn:oasis:names:tc:xacml:1.0:subject:subject-id"
                        DataType="http://www.w3.org/2001/XMLSchema#string"/>
                    </myns:Match>
                </myns:AllOf>
            """.format(username)
            )
        )

        roleREPS.attrib['Version'] = self._updatePolicyVersionNumber(
            roleREPS.attrib['Version']
        )
        roleREPS.find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Policy').attrib['Version'] = self._updatePolicyVersionNumber(
            roleREPS.find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Policy').attrib['Version']
        )

        return self._addOrUpdatePolicySet(clientToUse, et.tostring(roleREPS))


    def _apiAssignPermissionToRole(self, clientToUse, roleName, resourceName, permission):
        rolePPSString = self._getPPSByRole(clientToUse, roleName)
        if (rolePPSString == False):
            return False
        rolePPS = et.fromstring(rolePPSString)

        permissionRules = rolePPS.find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Policy')
        permissionRules.insert(
            1,
            et.fromstring("""
                <myns:Rule 
                    xmlns:myns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
                    RuleId="Permission:to:{1}:resource:{0}" 
                    Effect="Permit">
                    <myns:Target>
                        <myns:AnyOf>
                            <myns:AllOf>
                                <myns:Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
                                    <myns:AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">{0}</myns:AttributeValue>
                                    <myns:AttributeDesignator 
                                        MustBePresent="false" 
                                        Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource" 
                                        AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id" 
                                        DataType="http://www.w3.org/2001/XMLSchema#string"/>
                                </myns:Match>
                            </myns:AllOf>
                        </myns:AnyOf>
                        <myns:AnyOf>
                            <myns:AllOf>
                                <myns:Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
                                    <myns:AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">{1}</myns:AttributeValue>
                                    <myns:AttributeDesignator 
                                        MustBePresent="false" 
                                        Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action" 
                                        AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id" 
                                        DataType="http://www.w3.org/2001/XMLSchema#string"/>
                                </myns:Match>
                            </myns:AllOf>
                        </myns:AnyOf>
                    </myns:Target>
                </myns:Rule>
            """.format(resourceName, str(permission))
            )
        )

        rolePPS.attrib['Version'] = self._updatePolicyVersionNumber(
            rolePPS.attrib['Version']
        )
        rolePPS.find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Policy').attrib['Version'] = self._updatePolicyVersionNumber(
            rolePPS.find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Policy').attrib['Version']
        )

        return self._addOrUpdatePolicySet(clientToUse, et.tostring(rolePPS))


    def _apiRevokeUserFromRole(self, clientToUse, username, roleName):
        return self._revokeUserFromRoleWildcard(clientToUse, username, roleName)


    def _apiRevokePermissionFromRole(self, clientToUse, roleName, resourceName, permission):
        return self._revokePermissionFromRoleWildcard(clientToUse, roleName, resourceName)


    def _apiReadResource(self, clientToUse, username, assumedRoleName, resourceName):

        self.logging.info("Querying whether user " 
            + username 
            + " is assigned to role "
            + assumedRoleName
        )


        xacmlURRequest = """
        <myns:Request
            xmlns=""
            xmlns:myns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" 
            CombinedDecision="false" 
            ReturnPolicyIdList="false">
            <Attributes 
                xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
                Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject">
                <Attribute AttributeId="urn:oasis:names:tc:xacml:1.0:subject:subject-id" IncludeInResult="false">
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">{0}</AttributeValue>
                </Attribute>
            </Attributes>
            <Attributes 
                xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
                Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource">
                <Attribute AttributeId="urn:oasis:names:tc:xacml:2.0:subject:role" IncludeInResult="false">
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">{1}</AttributeValue>
                </Attribute>
            </Attributes>
            <Attributes 
                xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
                Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action">
                <Attribute AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id" IncludeInResult="false">
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">urn:oasis:names:tc:xacml:2.0:actions:enableRole</AttributeValue>
                </Attribute>
            </Attributes>
            <myns:Attributes Category="urn:oasis:names:tc:xacml:3.0:attribute-category:environment" />
        </myns:Request>
        """.format(username, assumedRoleName)

        with clientToUse.post(
            self.host + '/authzforce-ce/domains/' + self.domainCryptoACID + '/pdp',
            data = xacmlURRequest,
            headers = {'Accept': 'application/xml', 'Content-Type': 'application/xml;charset=UTF-8'}
        ) as responseEvaluatePolicySet:
            if (responseEvaluatePolicySet.status_code == 200):
                tree = et.fromstring(responseEvaluatePolicySet.content.decode('utf-8'))
                if (tree[0][0].text != "Permit"):
                    return False
            else:
                self.logging.error("Error ("
                    + str(responseEvaluatePolicySet.status_code)
                    + ") while getting policy set: " + responseEvaluatePolicySet.content.decode('utf-8')
                )
                return False


        self.logging.info("Querying whether role " 
            + assumedRoleName 
            + " has permission READ over resource"
            + resourceName
        )
        
        xacmlPARequest = """
        <myns:Request
            xmlns="" 
            xmlns:myns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" 
            CombinedDecision="false" 
            ReturnPolicyIdList="false">
            <Attributes 
                xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
                Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject">
                <Attribute AttributeId="urn:oasis:names:tc:xacml:2.0:subject:role" IncludeInResult="false">
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">{0}</AttributeValue>
                </Attribute>
            </Attributes>
            <Attributes 
                xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
                Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource">
                <Attribute AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id" IncludeInResult="false">
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">{1}</AttributeValue>
                </Attribute>
            </Attributes>
            <Attributes 
                xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
                Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action">
                <Attribute AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id" IncludeInResult="false">
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">{2}</AttributeValue>
                </Attribute>
            </Attributes>
            <myns:Attributes Category="urn:oasis:names:tc:xacml:3.0:attribute-category:environment" />
        </myns:Request>
        """.format(assumedRoleName, resourceName, "READ")
        with clientToUse.post(
            self.host + '/authzforce-ce/domains/' + self.domainCryptoACID + '/pdp',
            data = xacmlPARequest,
            headers = {'Accept': 'application/xml', 'Content-Type': 'application/xml;charset=UTF-8'}
        ) as responseEvaluatePolicySet:
            if (responseEvaluatePolicySet.status_code == 200):
                tree = et.fromstring(responseEvaluatePolicySet.content.decode('utf-8'))
                if (tree[0][0].text != "Permit"):
                    return False
            else:
                self.logging.error("Error ("
                    + str(responseEvaluatePolicySet.status_code)
                    + ") while getting policy set: " + responseEvaluatePolicySet.content.decode('utf-8')
                )
                return False

        return True


    def _apiWriteResource(self, clientToUse, userToUse, assumedRoleName, resourceName, resourceContent):

        self.logging.info("Querying whether user " 
            + userToUse 
            + " is assigned to role "
            + assumedRoleName
        )


        xacmlURRequest = """
        <myns:Request
            xmlns=""
            xmlns:myns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" 
            CombinedDecision="false" 
            ReturnPolicyIdList="false">
            <Attributes 
                xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
                Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject">
                <Attribute AttributeId="urn:oasis:names:tc:xacml:1.0:subject:subject-id" IncludeInResult="false">
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">{0}</AttributeValue>
                </Attribute>
            </Attributes>
            <Attributes 
                xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
                Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource">
                <Attribute AttributeId="urn:oasis:names:tc:xacml:2.0:subject:role" IncludeInResult="false">
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">{1}</AttributeValue>
                </Attribute>
            </Attributes>
            <Attributes 
                xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
                Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action">
                <Attribute AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id" IncludeInResult="false">
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">urn:oasis:names:tc:xacml:2.0:actions:enableRole</AttributeValue>
                </Attribute>
            </Attributes>
            <myns:Attributes Category="urn:oasis:names:tc:xacml:3.0:attribute-category:environment" />
        </myns:Request>
        """.format(userToUse, assumedRoleName)

        with clientToUse.post(
            self.host + '/authzforce-ce/domains/' + self.domainCryptoACID + '/pdp',
            data = xacmlURRequest,
            headers = {'Accept': 'application/xml', 'Content-Type': 'application/xml;charset=UTF-8'}
        ) as responseEvaluatePolicySet:
            if (responseEvaluatePolicySet.status_code == 200):
                tree = et.fromstring(responseEvaluatePolicySet.content.decode('utf-8'))
                if (tree[0][0].text != "Permit"):
                    return False
            else:
                self.logging.error("Error ("
                    + str(responseEvaluatePolicySet.status_code)
                    + ") while getting policy set: " + responseEvaluatePolicySet.content.decode('utf-8')
                )
                return False


        self.logging.info("Querying whether role " 
            + assumedRoleName 
            + " has permission WRITE over resource"
            + resourceName
        )
        
        xacmlPARequest = """
        <myns:Request
            xmlns="" 
            xmlns:myns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" 
            CombinedDecision="false" 
            ReturnPolicyIdList="false">
            <Attributes 
                xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
                Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject">
                <Attribute AttributeId="urn:oasis:names:tc:xacml:2.0:subject:role" IncludeInResult="false">
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">{0}</AttributeValue>
                </Attribute>
            </Attributes>
            <Attributes 
                xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
                Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource">
                <Attribute AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id" IncludeInResult="false">
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">{1}</AttributeValue>
                </Attribute>
            </Attributes>
            <Attributes 
                xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
                Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action">
                <Attribute AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id" IncludeInResult="false">
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">{2}</AttributeValue>
                </Attribute>
            </Attributes>
            <myns:Attributes Category="urn:oasis:names:tc:xacml:3.0:attribute-category:environment" />
        </myns:Request>
        """.format(assumedRoleName, resourceName, "WRITE")
        with clientToUse.post(
            self.host + '/authzforce-ce/domains/' + self.domainCryptoACID + '/pdp',
            data = xacmlPARequest,
            headers = {'Accept': 'application/xml', 'Content-Type': 'application/xml;charset=UTF-8'}
        ) as responseEvaluatePolicySet:
            if (responseEvaluatePolicySet.status_code == 200):
                tree = et.fromstring(responseEvaluatePolicySet.content.decode('utf-8'))
                if (tree[0][0].text != "Permit"):
                    return False
            else:
                self.logging.error("Error ("
                    + str(responseEvaluatePolicySet.status_code)
                    + ") while getting policy set: " + responseEvaluatePolicySet.content.decode('utf-8')
                )
                return False

        return True


    def _apiGetUsers(self, clientToUse):
        roleNames = self._apiGetRoles(clientToUse)
        if (roleNames == False):
            return False

        usernames = set()
        for currentRoleName in roleNames:
            currentREPS = self._getREPSByRole(clientToUse, currentRoleName)
            if (currentREPS == False):
                return False
            currentREPS = et.fromstring(currentREPS)

            usersAnyOf = currentREPS.find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Policy').find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Rule').find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Target').find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}AnyOf')
            for allOf in usersAnyOf.iter(tag="{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}AllOf"):
                usernames.add(allOf.find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Match').find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}AttributeValue').text)
        return list(usernames)
        

    def _apiGetRoles(self, clientToUse):
        policySets = self._getPolicySets(clientToUse)
        if (policySets == False):
            return False

        roleNames = set()
        for policySetLink in policySets.iter(tag="{http://www.w3.org/2005/Atom}link"):
            href = policySetLink.attrib['href']
            if (href != "root" and href != "CryptoAC:root:policy"):
                roleNames.add(href.split(":")[2])
        return list(roleNames)


    def _apiGetResources(self, clientToUse):
        roleNames = self._apiGetRoles(clientToUse)
        if (roleNames == False):
            return False

        resourceNames = set()
        for currentRoleName in roleNames:
            if (not (currentRoleName == self.adminName)):
                currentPPS = self._getPPSByRole(clientToUse, currentRoleName)
                if (currentPPS == False):
                    return False
                currentPPS = et.fromstring(currentPPS)
        
                resourceRules = currentPPS.find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Policy')
                for resourceRule in resourceRules.iter(tag="{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Rule"):
                    resourceNames.add(resourceRule.attrib["RuleId"].split(":")[4])

        return list(resourceNames)


    def _apiGetAssignments(self, clientToUse):
        roleNames = self._apiGetRoles(clientToUse)
        if (roleNames == False):
            return False

        assignments = {}
        for currentRoleName in roleNames:
            currentREPS = self._getREPSByRole(clientToUse, currentRoleName)
            if (currentREPS == False):
                return False
            currentREPS = et.fromstring(currentREPS)
            
            currentUsernames = set()
            usersAnyOf = currentREPS.find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Policy').find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Rule').find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Target').find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}AnyOf')
            for allOf in usersAnyOf.iter(tag="{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}AllOf"):
                currentUsernames.add(allOf.find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Match').find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}AttributeValue').text)
            assignments[currentRoleName] = list(currentUsernames)

        return assignments


    def _apiGetPermissions(self, clientToUse):
        roleNames = self._apiGetRoles(clientToUse)
        if (roleNames == False):
            return False

        permissions = {}
        for currentRoleName in roleNames:
            if (not (currentRoleName == self.adminName)):
                currentPPS = self._getPPSByRole(clientToUse, currentRoleName)
                if (currentPPS == False):
                    return False
                currentPPS = et.fromstring(currentPPS)

                currentResourceNames = []
                resourceRules = currentPPS.find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Policy')
                for resourceRule in resourceRules.iter(tag="{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Rule"):
                    currentResourceNames.append({
                        "resource":resourceRule.attrib["RuleId"].split(":")[4], 
                        "permission":resourceRule.attrib["RuleId"].split(":")[2]
                    })
                permissions[currentRoleName] = currentResourceNames

        return permissions




    # Create the CryptoAC domain
    def _createDomain(self, clientToUse):
        returnValue = False
        with open(self.domainRBAC) as domainRBACFile:
            domainRBACString = domainRBACFile.read()
            with clientToUse.post(
                self.host + '/authzforce-ce/domains/',
                data = domainRBACString,
                headers = {'Accept': 'application/xml', 'Content-type': 'application/xml;charset=UTF-8'}
            ) as responseCreateDomain:
                returnValue = (responseCreateDomain.status_code == 200)
                if (returnValue):
                    returnValue = self._getCryptoACDomainID(clientToUse)
                else:
                    self.logging.error("Error ("
                        + str(responseCreateDomain.status_code)
                        + ") while creating CryptoAC domain: " + responseCreateDomain.content.decode('utf-8')
                    )
        return returnValue


    # Get the ID of the CryptoAC domain
    def _getCryptoACDomainID(self, clientToUse):
        with clientToUse.get(
            self.host + '/authzforce-ce/domains/?externalId=domain:cryptoac',
            headers = {'Accept': 'application/xml'}
        ) as responseGetID:
            returnValue = (responseGetID.status_code == 200)
            if (returnValue):
                tree = et.fromstring(responseGetID.content.decode('utf-8'))
                self.domainCryptoACID = tree[0].attrib['href']
            else:
                self.logging.error("Error ("
                    + responseGetID.status_code
                    + ") while getting CryptoAC domain ID: " + responseGetID.content.decode('utf-8')
                )
            return returnValue


    # Set PRP properties
    def _setPRPProperties(self, clientToUse):
        returnValue = False
        with open(self.propertiesPRP) as propertiesPRPFile:
            propertiesPRPString = propertiesPRPFile.read()
            with clientToUse.put(
                self.host + '/authzforce-ce/domains/' + self.domainCryptoACID + '/pap/prp.properties',
                data = propertiesPRPString,
                headers = {'Accept': 'application/xml', 'Content-type': 'application/xml;charset=UTF-8'}
            ) as responseSetProperties:
                returnValue = (responseSetProperties.status_code == 200)
                if (not returnValue):
                    self.logging.error("Error ("
                        + str(responseSetProperties.status_code)
                        + ") while setting PRP properties: " + responseSetProperties.content.decode('utf-8')
                    )
        return returnValue


    # Load policy set from file and invoke _addOrUpdatePolicySet
    def _addOrUpdatePolicySetFromFile(self, clientToUse, policySetFile):
        with open(policySetFile) as file:
            policySetString = file.read()
            returnValue = self._addOrUpdatePolicySet(clientToUse, policySetString)
        return returnValue


    # Add or update policy set (the API is the same) given as an XML string
    def _addOrUpdatePolicySet(self, clientToUse, policySetString):
        with clientToUse.post(
            self.host + '/authzforce-ce/domains/' + self.domainCryptoACID + '/pap/policies',
            data = policySetString,
            headers = {'Accept': 'application/xml', 'Content-type': 'application/xml;charset=UTF-8'}
        ) as responseAddorUpdatePolicySet:
            returnValue = True # DECOMMENT THIS (responseAddorUpdatePolicySet.status_code == 200)
            if (not returnValue):
                self.logging.error("Error ("
                    + str(responseAddorUpdatePolicySet.status_code)
                    + ") while adding or updating a policy set: " + responseAddorUpdatePolicySet.content.decode('utf-8')
                )
        return returnValue


    # Set root policy
    def _settingTheRootPolicySet(self, clientToUse):
        with clientToUse.put(
            self.host + '/authzforce-ce/domains/' + self.domainCryptoACID + '/pap/pdp.properties',
            data = """
                <pdpPropertiesUpdate
                    xmlns="http://authzforce.github.io/rest-api-model/xmlns/authz/5">
                    <rootPolicyRefExpression>CryptoAC:root:policy</rootPolicyRefExpression>
                </pdpPropertiesUpdate>
            """,
            headers = {'Accept': 'application/xml', 'Content-type': 'application/xml;charset=UTF-8'}
        ) as responseSetRootPolicySet:
            returnValue = (responseSetRootPolicySet.status_code == 200)
            if (not returnValue):
                self.logging.error("Error ("
                    + str(responseSetRootPolicySet.status_code)
                    + ") while setting the root policy set: " + responseSetRootPolicySet.content.decode('utf-8')
                )
        return returnValue


    # Return the root policy set as an XML object
    # Return False if the request failed
    def _getRootPolicySet(self, clientToUse):
        rootPolicySetString = self._getPolicySetByID(clientToUse, "CryptoAC:root:policy")
        if (rootPolicySetString == False):
            return False
        else:
            return et.fromstring(rootPolicySetString)


    # Get the REPS of the role name
    def _getREPSByRole(self, clientToUse, roleName):
        return self._getPolicySetByID(
            clientToUse,
            "REPS:role:" + roleName
        )


    # Get the PPS of the role name
    def _getPPSByRole(self, clientToUse, roleName):
        return self._getPolicySetByID(
            clientToUse,
            "PPS:role:" + roleName
        )


    # Return the required policy set as a string
    # Return False if the request failed
    def _getPolicySetByID(self, clientToUse, policySetID):
        with clientToUse.get(
            self.host + '/authzforce-ce/domains/' + self.domainCryptoACID + '/pap/policies/' + policySetID + '/latest',
            headers = {'Accept': 'application/xml'}
        ) as responseGetPolicySet:
            if (responseGetPolicySet.status_code == 200):
                returnValue = responseGetPolicySet.content.decode('utf-8')
            else:
                returnValue = False
                self.logging.error("Error ("
                    + str(responseGetPolicySet.status_code)
                    + ") while getting policy set (id: " + policySetID + "): " + responseGetPolicySet.content.decode('utf-8')
                )
        return returnValue


    # Return the required policy set as a string
    # Return False if the request failed
    def _updatePolicyVersionNumber(self, oldVersion):
        return str(float(oldVersion) + 1.0)


    # Delete ([username], [roleName]) from
    # UR. Null values are wildcards. At least
    # one value is required
    def _revokeUserFromRoleWildcard(self, clientToUse, username=None, roleName=None):
        if (username == None and roleName == None):
            return False

        if (roleName == None):
            XACMLRBAC.policyLock.acquire()
            roleNames = self.rolesR
            XACMLRBAC.policyLock.release()
        else:
            roleNames = [roleName]

        self.logging.info("Getting all REPSs of involved roles")
        repss = set()
        for currentRoleName in roleNames:
            currentREPS = self._getREPSByRole(clientToUse, currentRoleName)
            if (currentREPS == False):
                return False
            repss.add(et.fromstring(currentREPS))


        self.logging.info("For each REPS, revoke the involved users")
        modifiedREPSs = set()
        for currentREPS in repss:
            usernames = set()
            if (username != None):
                usernames.add(username)
            else:
                usersAnyOf = currentREPS.find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Policy').find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Rule').find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Target').find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}AnyOf')
                for allOf in usersAnyOf.iter(tag="{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}AllOf"):
                    usernames.add(allOf.find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Match').find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}AttributeValue').text)

            modified = False
            allOfsToRemove = []
            for currentUsername in usernames:
                usersAnyOf = currentREPS.find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Policy').find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Rule').find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Target').find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}AnyOf')
                for allOf in usersAnyOf.iter(tag="{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}AllOf"):
                    if (currentUsername == allOf.find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Match').find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}AttributeValue').text):
                        allOfsToRemove.append(allOf)
                        modified = True
                for allOfToRemove in allOfsToRemove:
                    usersAnyOf.remove(allOfToRemove)
            if (modified):
                modifiedREPSs.add(currentREPS)


        for currentModifiedREPS in modifiedREPSs:
            currentModifiedREPS.attrib['Version'] = self._updatePolicyVersionNumber(
                currentModifiedREPS.attrib['Version']
            )
            currentModifiedREPS.find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Policy').attrib['Version'] = self._updatePolicyVersionNumber(
                currentModifiedREPS.find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Policy').attrib['Version']
            )
            if (self._addOrUpdatePolicySet(clientToUse, et.tostring(currentModifiedREPS)) == False):
                return False
        return True


    # Delete ([roleName], (-, [resourceName]))
    # from PA. Null values are wildcards. At
    # least one value is required
    def _revokePermissionFromRoleWildcard(self, clientToUse, roleName=None, resourceName=None):
        if (roleName == None and resourceName == None):
            return False

        if (roleName == None):
            XACMLRBAC.policyLock.acquire()
            roleNames = self.rolesR
            XACMLRBAC.policyLock.release()
        else:
            roleNames = [roleName]

        self.logging.info("Getting all PPS of involved roles")
        ppss = set()
        for currentRoleName in roleNames:
            currentPPS = self._getPPSByRole(clientToUse, currentRoleName)
            if (currentPPS == False):
                return False
            ppss.add(et.fromstring(currentPPS))


        self.logging.info("For each PPS, revoke the permission over the involved resource")
        modifiedPPSs = set()
        for currentPPS in ppss:
            resourceNames = set()
            if (resourceName != None):
                resourceNames.add(resourceName)
            else:
                resourceRules = currentPPS.find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Policy')
                for resourceRule in resourceRules.iter(tag="{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Rule"):
                    resourceNames.add(resourceRule.attrib["RuleId"].split(":")[4])

            modified = False
            resourceRulesToRemove = []
            for currentResourceName in resourceNames:
                resourceRules = currentPPS.find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Policy')
                for resourceRule in resourceRules.iter(tag="{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Rule"):
                    if (currentResourceName == resourceRule.attrib["RuleId"].split(":")[4]):
                        resourceRulesToRemove.append(resourceRule)
                        modified = True
                for resourceRuleToRemove in resourceRulesToRemove:
                    resourceRules.remove(resourceRuleToRemove)
            if (modified):
                modifiedPPSs.add(currentPPS)

        for currentModifiedPPS in modifiedPPSs:
            currentModifiedPPS.attrib['Version'] = self._updatePolicyVersionNumber(
                currentModifiedPPS.attrib['Version']
            )
            currentModifiedPPS.find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Policy').attrib['Version'] = self._updatePolicyVersionNumber(
                currentModifiedPPS.find('{urn:oasis:names:tc:xacml:3.0:core:schema:wd-17}Policy').attrib['Version']
            )
            if (self._addOrUpdatePolicySet(clientToUse, et.tostring(currentModifiedPPS)) == False):
                return False
        return True


    # Delete the given policy set
    def _deletePolicySetByID(self, clientToUse, policySetID):
        with clientToUse.delete(
            self.host + '/authzforce-ce/domains/' + self.domainCryptoACID + '/pap/policies/' + policySetID,
            headers = {'Accept': 'application/xml'}
        ) as responseDeletePolicySet:
            returnValue = (responseDeletePolicySet.status_code == 200)
            if (not returnValue):
                self.logging.error("Error ("
                    + str(responseDeletePolicySet.status_code)
                    + ") while deleting a policy set: " + responseDeletePolicySet.content.decode('utf-8')
                )
        return returnValue


    # Get all policy sets
    def _getPolicySets(self, clientToUse):
        with clientToUse.get(
            self.host + '/authzforce-ce/domains/' + self.domainCryptoACID + '/pap/policies/',
            headers = {'Accept': 'application/xml'}
        ) as responseGetPolicySets:
            returnValue = (responseGetPolicySets.status_code == 200)
            if (not returnValue):
                self.logging.error("Error ("
                    + str(responseGetPolicySets.status_code)
                    + ") while getting policy sets: " + responseGetPolicySets.content.decode('utf-8')
                )
            else:
                returnValue = et.fromstring(responseGetPolicySets.content.decode('utf-8'))
        return returnValue
