package org.example

import io.vertx.core.*
import io.vertx.core.http.HttpServerOptions
import io.vertx.ext.web.Router
import io.vertx.ext.web.RoutingContext
import io.vertx.ext.web.handler.SessionHandler
import io.vertx.ext.web.sstore.LocalSessionStore
import io.vertx.ext.web.sstore.SessionStore
import io.vertx.kotlin.coroutines.dispatcher
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import org.example.shared.LogToVertex


class MainVerticle : AbstractVerticle() {
    override fun start() {
        vertx = setUpVertx()
        GlobalScope.launch(vertx.dispatcher()) {
            val router: Router = Router.router(vertx)

            // Store session information on the server side
            val sessionStore: SessionStore = LocalSessionStore.create(vertx)
            val sessionHandler: SessionHandler = SessionHandler.create(sessionStore)
            router.route().handler(sessionHandler)
            router.get("/hello").handler { it.response().end("Hello from my route") }

            val issuer = "https://llk8vm.logto.app/oidc"
            val jwksuri = "https://llk8vm.logto.app/oidc/jwks"
            val logToVertex =  LogToVertex(vertx, issuer, jwksuri)
            val port = Integer.getInteger("http.port", 3000)
            val configuredRouter = logToVertex.configureSecurity(router)
            val options = HttpServerOptions()
            options.maxHeaderSize = 1024 * 16
            val httpServer = vertx.createHttpServer(options)
                .requestHandler(configuredRouter)
                .listen(port)
            getVertx().createHttpServer().requestHandler(configuredRouter).listen(port)
            println("Web server started on port $port")
        }


    }

    private fun setUpVertx(): Vertx {
        val vertexOptions = VertxOptions()
        vertexOptions.blockedThreadCheckInterval = 1000*60*60L
        return Vertx.vertx(vertexOptions)
    }

    private fun handleIndex(ctx: RoutingContext) {
        respondWithOk(
            ctx,
            "text/html",
            "<h1>Welcome to Vert.x Keycloak Example</h1><br><a href=\"/protected/\">Protected</a>"
        )
    }

    private fun respondWithOk(ctx: RoutingContext, contentType: String, content: String) {
        respondWith(ctx, 200, contentType, content)
    }

    private fun respondWithServerError(ctx: RoutingContext, contentType: String, content: String) {
        respondWith(ctx, 500, contentType, content)
    }

    private fun respondWith(ctx: RoutingContext, statusCode: Int, contentType: String, content: String) {
        ctx.request().response() //
            .setStatusCode(statusCode) //
            .putHeader("content-type", contentType) //
            .end(content)
    }

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {

            MainVerticle().start()
        }
    }

}

