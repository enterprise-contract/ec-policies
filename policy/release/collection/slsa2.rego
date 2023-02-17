#
# METADATA
# title: slsa2
# description: |-
#   Includes policy rules required to meet SLSA Level 2. Special attention must
#   be given to two requirements which are not covered by the policy rules in this
#   collection. The first is "Provenance - Authenticated" which is expected to be
#   performed when fetching the attestation via cosign or ec-cli. The second
#   requirement is "Provenace - Service Generated" which is a little more complex
#   to verify. By meeting both the "Provenance - Authenticated" AND "Build - Build
#   Service" requirements, we can have some confidence that this requirement is met
#   since Chains is a service that generates signed attestations with data obtained
#   from the build service (Tekton Pipelines).
package policy.release.collection.slsa2
