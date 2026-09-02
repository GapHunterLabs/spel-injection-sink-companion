package dev.gaphunter.spelinjectionsinkcompanion.detect

import com.intellij.psi.PsiAnnotation
import com.intellij.psi.PsiMethod

/**
 * A closed, known list of Spring MVC/JAX-RS annotations that mark a
 * method as an HTTP endpoint -- every parameter of such a method is
 * treated as an untrusted source, same convention (and same copy-per-
 * plugin, no shared library between repos) as
 * `unsafe-deserialization-sink-companion`'s own copy of this object.
 */
object ControllerEndpointSignals {

    private val METHOD_MAPPING_ANNOTATIONS = setOf(
        "PostMapping", "GetMapping", "PutMapping", "DeleteMapping", "PatchMapping", "RequestMapping",
        "POST", "GET", "PUT", "DELETE", "PATCH",
    )

    fun isEndpointMethod(method: PsiMethod): Boolean =
        method.modifierList.annotations.any { it.simpleNameMatches(METHOD_MAPPING_ANNOTATIONS) }

    private fun PsiAnnotation.simpleNameMatches(names: Set<String>): Boolean =
        nameReferenceElement?.referenceName in names
}
