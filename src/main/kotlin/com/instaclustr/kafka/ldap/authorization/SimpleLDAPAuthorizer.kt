package com.instaclustr.kafka.ldap.authorization

import com.instaclustr.kafka.ldap.Monitoring
import kafka.security.authorizer.AclAuthorizer
import org.apache.kafka.common.acl.AccessControlEntryFilter
import org.apache.kafka.common.acl.AclBinding
import org.apache.kafka.common.acl.AclBindingFilter
import org.apache.kafka.common.acl.AclPermissionType
import org.apache.kafka.common.resource.PatternType
import org.apache.kafka.common.resource.ResourcePatternFilter
import org.apache.kafka.common.resource.ResourceType
import org.apache.kafka.common.security.auth.KafkaPrincipal
import org.apache.kafka.server.authorizer.Action
import org.apache.kafka.server.authorizer.AuthorizableRequestContext
import org.apache.kafka.server.authorizer.AuthorizationResult
import org.slf4j.LoggerFactory


/**
 * A class adding LDAP group membership verification to Kafka SimpleAuthorizer
 * The overall prerequisite framework is the following
 * - Expecting LDAP groups in topic ACLS
 * - A principal is authorized through membership in group
 * - No group considerations, thus, empty ACL for group resource yield authorization
 * - No deny considerations, implicitly through non-membership
 *
 * See https://github.com/apache/kafka/tree/2.0/core/src/main/scala/kafka/security/auth
 */

class SimpleLDAPAuthorizer : AclAuthorizer() {

    override fun authorize( requestContext: AuthorizableRequestContext?, actions: MutableList<Action>?): MutableList<AuthorizationResult>? {

        var out = mutableListOf<AuthorizationResult>();
        val principal = requestContext?.principal()
        val host = requestContext?.clientAddress()?.hostAddress

        var superOut = super.authorize(requestContext,actions);

        actions?.forEachIndexed { index, action: Action ->
            // nothing to do if already authorized
            // this includes the configurable default handling for non ACLs case - ' allow.everyone.if.no.acl.found'
            //if (super.authorize(requestContext, actions)) return true


            var outAction = AuthorizationResult.ALLOWED;

            val lOperation = action?.operation()?.toString()
            val lResource = action?.resourcePattern()?.toString()
            val uuid = java.util.UUID.randomUUID().toString()
            val authContext =
                "principal=$principal, operation=$lOperation, remote_host=$host, resource=$lResource, uuid=$uuid"

            log.debug("Authorization Start -  $authContext")
            
            if( superOut[index] == AuthorizationResult.ALLOWED ){
                outAction = AuthorizationResult.ALLOWED;
            }else {
                var resourceType = action.resourcePattern()?.resourceType();
                var resourceName = action.resourcePattern();
                var resourcePattern = action.resourcePattern()?.toString();
                // TODO ResourceType.GROUP - under change in minor version - CAREFUL!
                // Warning! Assuming no group considerations, thus implicitly, always empty group access control lists
                if (action.resourcePattern()?.resourceType() == ResourceType.GROUP) {
                    log.debug("Authorization End - $authContext, status=authorized")
                    outAction = AuthorizationResult.ALLOWED;
                } else {

                    // TODO AclPermissionType.ALLOW - under change in minor version - CAREFUL!
                    // userAdd allow access control lists for resource and given operation

                    var aclBindingFilter = AclBindingFilter(
                        ResourcePatternFilter(resourceType, resourcePattern, PatternType.MATCH),
                        AccessControlEntryFilter(
                            principal?.name,
                            null,
                            action.operation(),
                            AclPermissionType.ALLOW
                        )
                    );

                    val sacls = acls(aclBindingFilter)

                    // switch to kotlin set, making testing easier
                    val acls = mutableSetOf<AclBinding>()
                    sacls.forEach() { acls += it }

                    log.debug(
                        "$lOperation has following Allow ACLs for $lResource: ${
                            acls.map {
                                it.entry().principal()
                            }
                        } uuid=$uuid"
                    )

                    // nothing to do if empty acl set
                    if (acls.isEmpty()) {
                        log.error("${Monitoring.AUTHORIZATION_FAILED.txt} - $authContext, status=denied, reason=EMPTY_ALLOW_ACL")
                        outAction = AuthorizationResult.DENIED;
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