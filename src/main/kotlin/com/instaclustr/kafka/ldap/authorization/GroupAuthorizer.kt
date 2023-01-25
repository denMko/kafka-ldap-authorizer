package com.instaclustr.kafka.ldap.authorization

import com.instaclustr.kafka.ldap.common.LDAPCache
import org.apache.kafka.common.acl.AclBinding
import org.apache.kafka.common.security.auth.KafkaPrincipal
import org.apache.kafka.server.authorizer.AuthorizationResult

/**
 * A class existing due to test capabilities
 * Instance of Kafka SimpleAuthorizer require logging to different server logs
 */

class GroupAuthorizer(private val uuid: String) : AutoCloseable {

    private fun userGroupMembershipIsCached(groups: List<String>, user: String): Boolean =
        groups.any { groupName -> LDAPCache.groupAndUserExists(groupName, user, uuid) }

    private fun userGroupMembershipInLDAP(groups: List<String>, user: String): Boolean =
        LDAPAuthorization.init(uuid)
            .use { ldap -> ldap.isUserMemberOfAny(user, groups) }
            .map { LDAPCache.groupAndUserAdd(it.groupName, user, uuid) }
            .isNotEmpty()

    fun authorize(principal: KafkaPrincipal, acls: Set<AclBinding>): AuthorizationResult =
        if (principal.name.let { user ->
                acls
                    .map { it.entry().principal().split(":")[1] }
                    .let { groups ->
                        // always check cache before ldap lookup
                        userGroupMembershipIsCached(groups, user) || userGroupMembershipInLDAP(groups, user)
                    }
            }) AuthorizationResult.ALLOWED else AuthorizationResult.DENIED;


    override fun close() {}
}