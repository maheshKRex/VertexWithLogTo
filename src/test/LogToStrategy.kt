package org.example.shared

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.config.*
import com.auth0.jwk.JwkProvider
import com.auth0.jwk.UrlJwkProvider

class LogtoStrategy(config: ApplicationConfig) {
    val logToUrl: String = config.property("LOGTO_URL").getString()
    val jwkProvider: JwkProvider = UrlJwkProvider(logToUrl + "/oidc/jwks")

    val jwtVerifier = JWT.configurable {
        verifier(jwkProvider) {
            // Additional configuration for issuer, audience, etc. if needed
            // issuer = logToUrl + "/oidc" // Uncomment if issuer validation needed
            // audience = "..." // Uncomment if audience validation needed
            acceptAlgorithms("ES384")
        }
        validate { credential ->
            // Optional custom validation logic for the JWT claims
            JWTPrincipal(credential.payload)
        }
    }
}

fun installLogtoAuthentication(application: Application, strategy: LogtoStrategy) {
    application.authentication {
        authentication {
            jwt {
                verifier(strategy.jwtVerifier)
                challengeTransformer { defaultSchemeChallengeTransformer(bearerAuthScheme) }
            }
        }
    }
}
