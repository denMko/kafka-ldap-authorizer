package com.instaclustr.kafka.ldap.authorization

import com.instaclustr.kafka.ldap.JAASContext
import com.instaclustr.kafka.ldap.LDAPConfig
import com.instaclustr.kafka.ldap.Monitoring
import com.unboundid.ldap.sdk.LDAPException
import com.unboundid.ldap.sdk.Filter
import com.unboundid.ldap.sdk.SearchRequest
import com.unboundid.ldap.sdk.SearchScope
import com.unboundid.ldap.sdk.LDAPSearchException
import com.instaclustr.kafka.ldap.common.LDAPBase
import com.instaclustr.kafka.ldap.toAdminDN
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import kotlin.system.measureTimeMillis

/**
 * A class verifying group membership with LDAP
 */

class LDAPAuthorization private constructor(
    private val uuid: String,
    val config: LDAPConfig.Config
) : LDAPBase(config) {

    // In authorization context, needs to bind the connection before compare-match between group and user
    // due to no anonymous access allowed for LDAP operations like search, compare, ...
    private val connectionAndBindIsOk: Boolean

    init {
        JAASContext.username = config.bindUsername
        JAASContext.password = config.bindPassword
        connectionAndBindIsOk = when {
            JAASContext.username.isEmpty() || JAASContext.password.isEmpty() -> false
            !ldapConnection.isConnected -> false
            else -> doBind(config.toAdminDN(JAASContext.username), JAASContext.password)
        }
    }

    private fun doBind(userDN: String, pwd: String): Boolean =
            try {
                log.debug("Binding information for authorization fetched from JAAS config file [$userDN]")
                measureTimeMillis { ldapConnection.bind(userDN, pwd) }
                        .also {
                            log.debug("Successfully bind to (${config.host},${config.port}) with $userDN")
                            log.info("${Monitoring.AUTHORIZATION_BIND_TIME.txt} $it")
                        }
                true
            } catch (e: LDAPException) {
                log.error("${Monitoring.AUTHORIZATION_BIND_FAILED.txt} $userDN to (${config.host},${config.port}) - ${e.diagnosticMessage}")
                false
            }

    private fun getDN(objectName: String, baseDN: String, uid: String): String =
        try {
            val filter = Filter.createEqualityFilter(uid, objectName)

            ldapConnection
                .search(SearchRequest(baseDN, SearchScope.SUB, filter, SearchRequest.NO_ATTRIBUTES))
                .let {
                    if (it.entryCount == 1) {
                        log.debug("for object $objectName found DN ${it.searchEntries[0].dn}")
                        it.searchEntries[0].dn
                    }
                    else {
                        log.error("${Monitoring.AUTHORIZATION_SEARCH_MISS.txt} $objectName under $baseDN ($uuid)")
                        ""
                    }
                }
        } catch (e: LDAPSearchException) {
            log.error("${Monitoring.AUTHORIZATION_SEARCH_FAILURE.txt} $objectName under $baseDN ($uuid)")
            ""
        }

    private fun getGroupMembers(groupDN: String): List<String> =
            try {
                if (groupDN.isNotEmpty())
                    ldapConnection.getEntry(groupDN)
                            ?.getAttributeValues(config.grpAttrName)
                            ?.map { it.lowercase() } ?: emptyList()
                else
                    emptyList()
            } catch (e: LDAPException) {
                log.error("${Monitoring.AUTHORIZATION_GROUP_FAILURE.txt} - ${config.grpAttrName} - for $groupDN ($uuid)")
                emptyList()
            }

    fun isUserMemberOfAny(user: String, groups: List<String>): Set<AuthorResult> {
        if (!connectionAndBindIsOk) {
            log.error("${Monitoring.AUTHORIZATION_LDAP_FAILURE.txt} $user membership in $groups ($uuid)")
            return emptySet()
        }

        val matching = groups.flatMap { groupName ->
            val groupDN = getDN(groupName, config.grpBaseDN, config.grpUid)
            val userDN = getDN(user, config.usrBaseDN, config.usrUid).lowercase()
            val members = getGroupMembers(groupDN)
            log.info("Group $groupDN has members $members, checking for presence of $user")

            members.filter { member -> member == userDN }.map { uDN ->
                AuthorResult(groupName, uDN)
            }
        }

        log.info("Checking $user for membership in $groups, found: $matching")
        return matching.toSet()
    }

    companion object {

        private val log: Logger = LoggerFactory.getLogger(LDAPAuthorization::class.java)

        fun init(uuid: String, configFile: String = ""): LDAPAuthorization = when (configFile.isEmpty()) {
            true -> LDAPAuthorization(uuid, LDAPConfig.getByClasspath())
            else -> LDAPAuthorization(uuid, LDAPConfig.getBySource(configFile))
        }
    }
}