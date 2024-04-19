package org.example.shared

import io.vertx.core.Future
import io.vertx.core.Handler
import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.ext.auth.JWTOptions
import io.vertx.ext.auth.jwt.*

import io.vertx.ext.web.handler.JWTAuthHandler
import io.vertx.ext.auth.oauth2.OAuth2Auth
//import io.vertx.ext.auth.oauth2.OAuth2ClientOptions
import io.vertx.ext.web.Router
import io.vertx.ext.web.RoutingContext
import io.vertx.ext.web.client.WebClient
import io.vertx.ext.web.codec.BodyCodec
import io.vertx.kotlin.coroutines.await
import java.util.stream.Collectors


class LogToVertex(val vertx: Vertx, val issuer: String, val jwksUri: String) {

     suspend fun configureSecurity(router: Router): Router {
        val setupJWTAuthResponse = setupJwtAuth()
        setupJWTAuthResponse?.await()
        if (setupJWTAuthResponse?.isComplete == true) {
            if (setupJWTAuthResponse.succeeded()) {
                val jwtAuth = setupJWTAuthResponse.result()
                val jwtAuthHandler = JWTAuthHandler.create(jwtAuth)
                router.route("/api/*").handler(jwtAuthHandler);
                router.get("/api/").handler{ it.response().end("Hello from my protected route") } // Requires authentication
                //router.get("/api/secret").handler(jwtAuthHandler) // Requires authentication
                //router.get("/api/profile").handler(RoutingContext::next) // Public access
            } else {
                throw Exception("failed to setup JWT Auth")
            }
        }

        return router
    }

    private fun setupJwtAuth(): Future<JWTAuth>? {
        val webClient = WebClient.create(vertx)
        return Future.future { promise ->
            try {
                webClient.getAbs(jwksUri)
                    .`as`(BodyCodec.jsonObject())
                    .send { ar ->
                        if (ar.succeeded() && ar.result().statusCode() == 200) {
                            val keys = ar.result().body().getJsonArray("keys")
                            val jwks = (keys.getList() as List<Any?>).stream()
                                .map<JsonObject> { o: Any? ->
                                    JsonObject(
                                        o as Map<String?, Any?>?
                                    )
                                }
                                .collect(Collectors.toList<JsonObject>())
                            val jwtOptions = JWTOptions().setIssuer(issuer)
                            val jwtAuthOptions = JWTAuthOptions()
                                .setJwks(jwks)
                                .setJWTOptions(jwtOptions)
                            //.setPermissionsClaimKey(jwtConfig.getString("permissionClaimsKey", "realm_access/roles"))

                            promise.complete(JWTAuth.create(vertx, jwtAuthOptions))
                        } else {
                            throw RuntimeException("Runtime Exception getting jwks keys failed")
                        }
                    }
            } catch (e: Throwable) {
                promise.fail("Could not fetch JWKS from URI: $jwksUri $e")
            }
        }
    }

}


