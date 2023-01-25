package com.instaclustr.kafka.ldap.authorization

import com.instaclustr.kafka.ldap.Monitoring
import org.apache.kafka.metadata.authorizer.StandardAuthorizer
import org.apache.kafka.common.acl.AccessControlEntryFilter
import org.apache.kafka.common.acl.AclBinding
import org.apache.kafka.common.acl.AclBindingFilter
import org.apache.kafka.common.acl.AclOperation
import org.apache.kafka.common.acl.AclPermissionType
import org.apache.kafka.common.resource.PatternType
import org.apache.kafka.common.resource.ResourcePatternFilter
import org.apache.kafka.common.resource.ResourceType
import org.apache.kafka.common.security.auth.KafkaPrincipal
import org.apache.kafka.server.authorizer.Action
import org.apache.kafka.server.authorizer.AuthorizableRequestContext
import org.apache.kafka.server.authorizer.AuthorizationResult
import org.slf4j.LoggerFactory
import java.util.Collections
import java.util.EnumSet

import org.apache.kafka.common.acl.AclOperation.ALL
import org.apache.kafka.common.acl.AclOperation.ALTER
import org.apache.kafka.common.acl.AclOperation.ALTER_CONFIGS
import org.apache.kafka.common.acl.AclOperation.DELETE
import org.apache.kafka.common.acl.AclOperation.DESCRIBE
import org.apache.kafka.common.acl.AclOperation.DESCRIBE_CONFIGS
import org.apache.kafka.common.acl.AclOperation.READ
import org.apache.kafka.common.acl.AclOperation.WRITE


/**
 * A class adding LDAP group membership verification to KRaft Kafka StandardAuthorizer
 * The overall prerequisite framework is the following
 * - Expecting LDAP groups in topic ACLS
 * - A principal is authorized through membership in group
 * - No group considerations, thus, empty ACL for group resource yield authorization
 * - No deny considerations, implicitly through non-membership
 *
 * See https://github.com/apache/kafka/blob/trunk/metadata/src/main/java/org/apache/kafka/metadata/authorizer/StandardAuthorizer.java
 */

class SimpleLDAPAuthorizer : StandardAuthorizer() {

    private val IMPLIES_DESCRIBE : Set<AclOperation> = Collections.unmodifiableSet(
        EnumSet.of(DESCRIBE, READ, WRITE, DELETE, ALTER))

    private val IMPLIES_DESCRIBE_CONFIGS : Set<AclOperation> = Collections.unmodifiableSet(
        EnumSet.of(DESCRIBE_CONFIGS, ALTER_CONFIGS))

    override fun authorize( requestContext: AuthorizableRequestContext?, actions: MutableList<Action>?): MutableList<AuthorizationResult>? {

        var out = mutableListOf<AuthorizationResult>();
        val principal = requestContext?.principal()
        val host = requestContext?.clientAddress()?.hostAddress

        var superOut = super.authorize(requestContext, actions);

        actions?.forEachIndexed { index, action: Action ->
            // nothing to do if already authorized
            // this includes the configurable default handling for non ACLs case - 'allow.everyone.if.no.acl.found'
            //if (super.authorize(requestContext, actions)) return true

            val lOperation = action.operation()?.toString()
            val lResource = action.resourcePattern()?.toString()
            val uuid = java.util.UUID.randomUUID().toString()
            val authContext =
                "principal=$principal, operation=$lOperation, remote_host=$host, resource=$lResource, uuid=$uuid"

            var outAction = AuthorizationResult.DENIED;


            if( superOut[index] == AuthorizationResult.ALLOWED ){
                outAction = AuthorizationResult.ALLOWED;
            } else {
                log.debug("Authorization Start -  $authContext")
                var resourceType = action.resourcePattern()?.resourceType();
                var resourceName = action.resourcePattern()?.name();

                // TODO ResourceType.GROUP - under change in minor version - CAREFUL!
                // Warning! Assuming no group considerations, thus implicitly, always empty group access control lists
                if (action.resourcePattern()?.resourceType() == ResourceType.GROUP) {
                    log.debug("Authorization End - $authContext, status=authorized")
                    outAction = AuthorizationResult.ALLOWED;
                } else {

                    // TODO AclPermissionType.ALLOW - under change in minor version - CAREFUL!
                    // userAdd allow access control lists for resource and given operation

                    var aclBindingFilter = AclBindingFilter(
                        ResourcePatternFilter(resourceType, resourceName, PatternType.MATCH),
                        AccessControlEntryFilter(
                            null,
                            null,
                            //action.operation(),
                            AclOperation.ANY,
                            AclPermissionType.ALLOW
                        )
                    );

                    val sacls = acls(aclBindingFilter)

                    // switch to kotlin set, making testing easier
                    val acls = mutableSetOf<AclBinding>()
                    sacls.forEach() {
                        val aclOperation = it.entry().operation()
                        var doAuthorize = true

                        log.debug("Request operation is ${action.operation()}. Acl operation is $aclOperation")
                        if(aclOperation != ALL && aclOperation != action.operation()){
                            doAuthorize = when(action.operation()) {
                                DESCRIBE ->
                                    IMPLIES_DESCRIBE.contains(aclOperation)
                                DESCRIBE_CONFIGS ->
                                    IMPLIES_DESCRIBE_CONFIGS.contains(aclOperation)
                                else -> false
                            }
                        }
                        if(doAuthorize) acls += it
                    }

                    log.debug(
                        "$lOperation has following Allow ACLs for $lResource: ${
                            acls.map {
                                it.entry().principal().split(":")[1]
                            }
                        } uuid=$uuid"
                    )

                    // nothing to do if empty acl set
                    if (acls.isEmpty()) {
                        log.error("${Monitoring.AUTHORIZATION_FAILED.txt} - $authContext, status=denied, reason=EMPTY_ALLOW_ACL")
                        // outAction = AuthorizationResult.DENIED;
                    } else {
                        // verify membership, either cached or through LDAP - see GroupAuthorizer
                        val anonymous = KafkaPrincipal(KafkaPrincipal.USER_TYPE, "ANONYMOUS")
                        val isAuthorized = GroupAuthorizer(uuid).use { it.authorize(principal ?: anonymous, acls) }

                        when (isAuthorized) {
                            AuthorizationResult.ALLOWED -> log.debug("Authorization End - $authContext, status=authorized")
                            AuthorizationResult.DENIED -> log.error("${Monitoring.AUTHORIZATION_FAILED.txt} - $authContext, status=denied")
                        }

                        outAction = isAuthorized;
                    }
                }
            }

            out.add(outAction);

        }
        return out;
    }

    companion object {
        private val log = LoggerFactory.getLogger(SimpleLDAPAuthorizer::class.java)
    }
}