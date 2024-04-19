package org.example.shared


import com.auth0.jwk.*
import com.auth0.jwt.*
import com.auth0.jwt.algorithms.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.http.content.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.Serializable
import java.io.*
import java.security.*
import java.security.interfaces.*
import java.security.spec.*
import java.util.*
import java.util.concurrent.*

@Serializable
data class User(val username: String, val password: String)

fun Application.main() {
    install(ContentNegotiation) {
        json()
    }
    val privateKeyString = environment.config.property("jwt.privateKey").getString()
    val issuer = environment.config.property("jwt.issuer").getString()
    val audience = environment.config.property("jwt.audience").getString()
    val myRealm = environment.config.property("jwt.realm").getString()
    val jwkProvider = JwkProviderBuilder(issuer)
        .cached(10, 24, TimeUnit.HOURS)
        .rateLimited(10, 1, TimeUnit.MINUTES)
        .build()
    install(Authentication) {
        jwt("auth-jwt") {
            realm = myRealm
            verifier(jwkProvider, issuer) {
                acceptLeeway(3)
            }
            validate { credential ->
                if (credential.payload.getClaim("username").asString() != "") {
                    JWTPrincipal(credential.payload)
                } else {
                    null
                }
            }
            challenge { defaultScheme, realm ->
                call.respond(HttpStatusCode.Unauthorized, "Token is not valid or has expired")
            }
        }
    }
    routing {
        post("/login") {
            val user = call.receive<User>()
            // Check username and password
            // ...
            val publicKey = jwkProvider.get("6f8856ed-9189-488f-9011-0ff4b6c08edc").publicKey
            val keySpecPKCS8 = PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyString))
            val privateKey = KeyFactory.getInstance("RSA").generatePrivate(keySpecPKCS8)
            val token = JWT.create()
                .withAudience(audience)
                .withIssuer(issuer)
                .withClaim("username", user.username)
                .withExpiresAt(Date(System.currentTimeMillis() + 60000))
                .sign(Algorithm.RSA256(publicKey as RSAPublicKey, privateKey as RSAPrivateKey))
            call.respond(hashMapOf("token" to token))
        }

        authenticate("auth-jwt") {
            get("/hello") {
                val principal = call.principal<JWTPrincipal>()
                val username = principal!!.payload.getClaim("username").asString()
                val expiresAt = principal.expiresAt?.time?.minus(System.currentTimeMillis())
                call.respondText("Hello, $username! Token is expired at $expiresAt ms.")
            }
        }
        static(".well-known") {
            staticRootFolder = File("certs")
            file("jwks.json")
        }
    }
    private fun handleUserPage(ctx: RoutingContext) {
        val user: OAuth2TokenImpl = ctx.user() as OAuth2TokenImpl

        if (user == null) {
            respondWithServerError(ctx, "text/html", kotlin.String.format("<h1>Request failed %s</h1>", "user missing"))
            return
        }

        // extract username from IDToken, there are many more claims like (email, givenanme, familyname etc.) available
        val username: String = user.idToken().getString("preferred_username")

        val content = kotlin.String.format(
            "<h1>User Page: %s @%s</h1><a href=\"/protected/\">Protected Area</a>",
            username,
            Instant.now()
        )
        respondWithOk(ctx, "text/html", content)
    }

    private fun handleAdminPage(ctx: RoutingContext) {
        val user: OAuth2TokenImpl = ctx.user() as OAuth2TokenImpl

        if (user == null) {
            respondWithServerError(ctx, "text/html", kotlin.String.format("<h1>Request failed %s</h1>", "user missing"))
            return
        }

        // check for realm-role "admin"
        user.isAuthorized("realm:admin") { res ->
            if (!res.succeeded() || !res.result()) {
                respondWith(ctx, 403, "text/html", "<h1>Forbidden</h1>")
                return@isAuthorized
            }
            val username: String = user.idToken().getString("preferred_username")

            val content = kotlin.String.format(
                "<h1>Admin Page: %s @%s</h1><a href=\"/protected/\">Protected Area</a>",
                username,
                Instant.now()
            )
            respondWithOk(ctx, "text/html", content)
        }
    }

    private fun createUserInfoHandler(webClient: WebClient, userInfoUrl: String): Handler<RoutingContext> {
        return Handler<RoutingContext> { ctx: RoutingContext ->
            val user: OAuth2TokenImpl = ctx.user() as OAuth2TokenImpl
            if (user == null) {
                respondWithServerError(
                    ctx,
                    "text/html",
                    kotlin.String.format("<h1>Request failed %s</h1>", "user missing")
                )
                return@Handler
            }

            // We use the userinfo endpoint as a straw man "backend" to demonstrate backend calls with bearer token
            val userInfoEndpointUri = URI.create(userInfoUrl)
            webClient
                .get(
                    userInfoEndpointUri.port,
                    userInfoEndpointUri.host,
                    userInfoEndpointUri.path
                ) // use the access token for calls to other services protected via JWT Bearer authentication
                .bearerTokenAuthentication(user.opaqueAccessToken())
                .`as`(BodyCodec.jsonObject())
                .send { ar ->
                    if (!ar.succeeded()) {
                        respondWith(ctx, 500, "application/json", "{}")
                        return@send
                    }
                    val body: JsonObject = ar.result().body()
                    respondWithOk(ctx, "application/json", body.encode())
                }
        }
    }

    private fun handleLogout(ctx: RoutingContext) {
        val user: OAuth2TokenImpl = ctx.user() as OAuth2TokenImpl

        if (user == null) {
            respondWithServerError(ctx, "text/html", kotlin.String.format("<h1>Request failed %s</h1>", "user missing"))
            return
        }

        user.logout { res ->
            if (!res.succeeded()) {
                // the user might not have been logged out, to know why:
                respondWithServerError(
                    ctx,
                    "text/html",
                    java.lang.String.format("<h1>Logout failed %s</h1>", res.cause())
                )
                return@logout
            }
            ctx.session().destroy()
            ctx.response().setStatusCode(302).putHeader("location", "/?logout=true").end()
        }
    }

    private fun handleGreet(ctx: RoutingContext) {
        val user: OAuth2TokenImpl = ctx.user() as OAuth2TokenImpl

        if (user == null) {
            respondWithServerError(ctx, "text/html", kotlin.String.format("<h1>Logout failed %s</h1>", "user missing"))
            return
        }

        val username: String = user.idToken().getString("preferred_username")
        val displayName: String = user.idToken().getString("name")

        val greeting = kotlin.String.format(
            "<h1>Hi %s (%s) @%s</h1><ul>" +
                    "<li><a href=\"/protected/user\">User Area</a></li>" +
                    "<li><a href=\"/protected/admin\">Admin Area</a></li>" +
                    "<li><a href=\"/protected/userinfo\">User Info (Remote Call)</a></li>" +
                    "</ul>", username, displayName, Instant.now()
        )

        val logoutForm = createLogoutForm(ctx)

        respondWithOk(ctx, "text/html", greeting + logoutForm)
    }

    private fun createLogoutForm(ctx: RoutingContext): String {
        val csrfToken: String = ctx.get(CSRFHandler.DEFAULT_HEADER_NAME)

        return ("<form action=\"/logout\" method=\"post\" enctype='multipart/form-data'>"
                + java.lang.String.format(
            "<input type=\"hidden\" name=\"%s\" value=\"%s\">",
            CSRFHandler.DEFAULT_HEADER_NAME,
            csrfToken
        )
                + "<button>Logout</button></form>")
    }

    private fun configureRoutes(router: Router, webClient: WebClient, oauth2Auth: OAuth2Auth) {
        router.get("/").handler { ctx: RoutingContext -> this.handleIndex(ctx) }

        router.get("/protected/").handler { ctx: RoutingContext -> this.handleGreet(ctx) }
        router.get("/protected/user").handler { ctx: RoutingContext -> this.handleUserPage(ctx) }
        router.get("/protected/admin").handler { ctx: RoutingContext -> this.handleAdminPage(ctx) }

        // extract discovered userinfo endpoint url
        val userInfoUrl: String = (oauth2Auth as OAuth2AuthProviderImpl).getConfig().getUserInfoPath()
        router.get("/protected/userinfo").handler(createUserInfoHandler(webClient, userInfoUrl))

        router.post("/logout").handler { ctx: RoutingContext -> this.handleLogout(ctx) }
    }

/*class JWTAuthHandler(val oauth2AuthProvider: OAuth2Auth) : Handler<RoutingContext> {
    override fun handle(context: RoutingContext) {
        oauth2AuthProvider.authenticate(JsonObject(context.request().headers().get("Authorization"))) { result ->
            if (result.failed()) {
                context.fail(401) // Unauthorized if token validation fails
                return@authenticate
            }

            // Continue processing if token validation succeeds
            context.next()
        }
        *//*//*/ You can add custom logic here to validate additional claims or perform actions before continuing
        if (context.user() == null) {
            context.fail(401) // Unauthorized if no user is found
        } else {
            context.next() // Continue processing the request
        }*//*
    }
}*/

}