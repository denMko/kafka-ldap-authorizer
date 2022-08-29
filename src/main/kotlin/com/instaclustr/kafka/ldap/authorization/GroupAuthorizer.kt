package com.instaclustr.kafka.ldap.authorization

import com.instaclustr.kafka.ldap.LDAPConfig
import com.instaclustr.kafka.ldap.common.LDAPCache
import com.instaclustr.kafka.ldap.toUserDNNodes
import org.apache.kafka.common.acl.AclBinding
import org.apache.kafka.common.security.auth.KafkaPrincipal
import org.apache.kafka.server.authorizer.AuthorizationResult

/**
 * A class existing due to test capabilities
 * Instance of Kafka SimpleAuthorizer require logging to different server logs
 */

class GroupAuthorizer(private val uuid: String) : AutoCloseable {

    private fun userGroupMembershipIsCached(groups: List<String>, userDNs: List<String>): Boolean =
            userDNs.any { userDN -> groups.any { groupName -> LDAPCache.groupAndUserExists(groupName, userDN, uuid) } }

    private fun userGroupMembershipInLDAP(groups: List<String>, userDNs: List<String>): Boolean =
            LDAPAuthorization.init(uuid,"/opt/tibco/akd/core/bin/../libs/ldapconfig.yaml")
                    .use { ldap -> ldap.isUserMemberOfAny(userDNs, groups) }
                    .map { LDAPCache.groupAndUserAdd(it.groupName, it.userDN, uuid) }
                    .isNotEmpty()

    fun authorize(principal: KafkaPrincipal, acls: Set<AclBinding>): AuthorizationResult =
            if (LDAPConfig.getByClasspath().toUserDNNodes(principal.name).let { userDNs ->
                acls
                        .map { it.entry().principal() }
                        .let { groups ->
                            // always check cache before ldap lookup
                            userGroupMembershipIsCached(groups, userDNs) || userGroupMembershipInLDAP(groups, userDNs)
                        }
            }) AuthorizationResult.ALLOWED else AuthorizationResult.DENIED;


    override fun close() {}
}