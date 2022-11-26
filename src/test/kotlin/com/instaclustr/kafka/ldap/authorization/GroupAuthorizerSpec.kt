package com.instaclustr.kafka.ldap.authorization

import com.instaclustr.kafka.ldap.JAASContext
import com.instaclustr.kafka.ldap.common.InMemoryLDAPServer
import org.amshove.kluent.shouldBeEqualTo
import org.apache.kafka.common.acl.*
import org.apache.kafka.common.resource.PatternType
import org.apache.kafka.common.resource.ResourcePattern
import org.apache.kafka.common.resource.ResourceType
import org.apache.kafka.common.security.auth.KafkaPrincipal
import org.apache.kafka.server.authorizer.AuthorizationResult
import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe
import java.util.*

object GroupAuthorizerSpec : Spek({

    // create read allowance for ldap group
    fun cReadAS(ldapGroup: String): Set<AclBinding> =
            setOf(
                AclBinding(
                    ResourcePattern(ResourceType.GROUP,ResourcePattern.WILDCARD_RESOURCE,PatternType.UNKNOWN),
                    AccessControlEntry(
                        KafkaPrincipal(KafkaPrincipal.USER_TYPE, ldapGroup).name,
                        "*",
                        AclOperation.READ,
                        AclPermissionType.ALLOW
                    )
                    )
            )




    // create describe allowance for ldap group
    fun cDescribeAS(ldapGroup1: String, ldapGroup2: String): Set<AclBinding> =
            setOf(
                    AclBinding(
                        ResourcePattern(ResourceType.GROUP, ResourcePattern.WILDCARD_RESOURCE, PatternType.UNKNOWN),
                        AccessControlEntry(
                            KafkaPrincipal(KafkaPrincipal.USER_TYPE, ldapGroup1).name,
                            "*",
                            AclOperation.DESCRIBE,
                            AclPermissionType.ALLOW
                        )
                    ),
                    AclBinding(
                        ResourcePattern(ResourceType.GROUP, ResourcePattern.WILDCARD_RESOURCE, PatternType.UNKNOWN),
                        AccessControlEntry(
                            KafkaPrincipal(KafkaPrincipal.USER_TYPE, ldapGroup2).name,
                            "*",
                            AclOperation.DESCRIBE,
                            AclPermissionType.ALLOW
                        )
                    )
            )

    // create write allowance for ldap group
    fun cWriteAS(ldapGroup: String): Set<AclBinding> =
            setOf(
                    AclBinding(
                        ResourcePattern(ResourceType.GROUP, ResourcePattern.WILDCARD_RESOURCE, PatternType.UNKNOWN),
                        AccessControlEntry(
                            KafkaPrincipal(KafkaPrincipal.USER_TYPE, ldapGroup).name,
                            "*",
                            AclOperation.WRITE,
                            AclPermissionType.ALLOW
                        )
                    )
            )

    // helper function for creating KafkaPrincipal
    fun createKP(userName: String): KafkaPrincipal = KafkaPrincipal(KafkaPrincipal.USER_TYPE, userName)

    // set the JAAS config in order to do successful init of LDAPAuthorization
    JAASContext.username = "igroup"
    JAASContext.password = "itest"

    describe("GroupAuthorizer class test specifications") {

        beforeGroup {
            InMemoryLDAPServer.start()
        }

        val refUserDescribeACL = mapOf(
                Triple("srvp01", listOf("KC-tpc-01", "KP-tpc-01"), "tpc-01") to AuthorizationResult.DENIED,
                Triple("srvc01", listOf("KC-tpc-01", "KP-tpc-01"), "tpc-01") to AuthorizationResult.DENIED,

                Triple("srvp01", listOf("KC-tpc-02", "KP-tpc-02"), "tpc-02") to AuthorizationResult.ALLOWED,
                Triple("srvc01", listOf("KC-tpc-02", "KP-tpc-02"), "tpc-02") to AuthorizationResult.DENIED,

                Triple("srvp01", listOf("KC-tpc-03", "KP-tpc-03"), "tpc-03") to AuthorizationResult.DENIED,
                Triple("srvc01", listOf("KC-tpc-03", "KP-tpc-03"), "tpc-03") to AuthorizationResult.ALLOWED
        )

        val refUserWriteACL = mapOf(
                Triple("srvp01", "KP-tpc-01", "tpc-01") to AuthorizationResult.DENIED,
                Triple("srvp01", "KP-tpc-02", "tpc-02") to AuthorizationResult.ALLOWED,
                Triple("srvp01", "KP-tpc-03", "tpc-03") to AuthorizationResult.DENIED
        )

        val refUserReadACL = mapOf(
                Triple("srvc01", "KC-tpc-01", "tpc-01") to AuthorizationResult.DENIED,
                Triple("srvc01", "KC-tpc-02", "tpc-02") to AuthorizationResult.DENIED,
                Triple("srvc01", "KC-tpc-03", "tpc-03") to AuthorizationResult.ALLOWED
                )

        context("describe allowance") {

            refUserDescribeACL.forEach { tr, result ->

                it("should return $result for user ${tr.first} trying describe on topic ${tr.third}") {

                    GroupAuthorizer(UUID.randomUUID().toString())
                            .authorize(
                                    createKP(tr.first),
                                    cDescribeAS(tr.second.first(), tr.second.last())
                            ).toString() shouldBeEqualTo result.toString()
                }
            }
        }

        context("write allowance") {

            refUserWriteACL.forEach { tr, result ->

                it("should return $result for user ${tr.first} trying write on topic ${tr.third}") {

                    GroupAuthorizer(UUID.randomUUID().toString())
                            .authorize(
                                    createKP(tr.first),
                                    cWriteAS(tr.second)
                            ).toString() shouldBeEqualTo result.toString()
                }
            }
        }

        context("read allowance") {

            refUserReadACL.forEach { tr, result ->

                it("should return $result for user ${tr.first} trying read on topic ${tr.third}") {

                    GroupAuthorizer(UUID.randomUUID().toString())
                            .authorize(
                                    createKP(tr.first),
                                    cReadAS(tr.second)
                            ).toString() shouldBeEqualTo result.toString()
                }
            }
        }

        afterGroup {
            InMemoryLDAPServer.stop()
        }
    }
})