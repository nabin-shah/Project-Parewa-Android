/*
 * Copyright 2025 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.signalservice.api.message

import kotlinx.coroutines.runBlocking
import org.signal.core.models.ServiceId
import org.signal.libsignal.net.MultiRecipientMessageResponse
import org.signal.libsignal.net.MultiRecipientSendAuthorization
import org.signal.libsignal.net.MultiRecipientSendFailure
import org.signal.libsignal.net.RequestResult
import org.signal.libsignal.net.UnauthMessagesService
import org.signal.network.NetworkResult
import org.signal.network.websocket.WebSocketRequestMessage
import org.signal.network.websocket.WebsocketResponse
import org.signal.network.websocket.post
import org.signal.network.websocket.put
import org.whispersystems.signalservice.api.crypto.SealedSenderAccess
import org.whispersystems.signalservice.api.fromWebSocketRequest
import org.whispersystems.signalservice.api.websocket.SignalWebSocket
import org.whispersystems.signalservice.internal.push.OutgoingPushMessageList
import org.whispersystems.signalservice.internal.push.SendMessageResponse
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.MediaType.Companion.toMediaType
import org.signal.core.util.logging.Log
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import org.signal.network.exceptions.NonSuccessfulResponseCodeException

/**
 * Collection of endpoints for operating on messages.
 */
class MessageApi(
  private val authWebSocket: SignalWebSocket.AuthenticatedWebSocket,
  private val unauthWebSocket: SignalWebSocket.UnauthenticatedWebSocket
) {

  companion object {
    /**
     * Adjust the default parsing of [SendMessageResponse] to set the non-server returned [SendMessageResponse.sentUnidentfied]
     * flag on the model.
     */
    private val sendMessageResponseConverter = object : NetworkResult.WebSocketResponseConverter<SendMessageResponse> {
      override fun convert(response: WebsocketResponse): NetworkResult<SendMessageResponse> {
        return if (response.status == 200) {
          response.toSuccess(SendMessageResponse::class)
            .map { it.apply { setSentUnidentfied(response.isUnidentified) } }
        } else {
          response.toStatusCodeError()
        }
      }
    }
  }

  /**
   * Sends a message to a single recipient, using the appropriate initial authentication style based on presence of [sealedSenderAccess], but
   * will automatically fallback to auth if that fails specifically because of an invalid [sealedSenderAccess].
   *
   * PUT /v1/messages/[messageList]`.destination`?story=[story]
   * - 200: Success
   * - 401: Message is not a story and authorization or [sealedSenderAccess] is missing or incorrect
   * - 404: Message is not a story and recipient is not a registered Signal user
   * - 409: Mismatched devices
   * - 410: Stale devices
   * - 428: Sender proof required
   */
  fun sendMessage(messageList: OutgoingPushMessageList, sealedSenderAccess: SealedSenderAccess?, story: Boolean): NetworkResult<SendMessageResponse> {
    Log.i("MessageApi", "Parewa MVP: Bypassing WebSocket and using HTTP fallback for PUT /v1/messages/${messageList.destination}")
    return try {
      val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
      })

      val sslContext = SSLContext.getInstance("SSL")
      sslContext.init(null, trustAllCerts, java.security.SecureRandom())
      val sslSocketFactory = sslContext.socketFactory

      val client = OkHttpClient.Builder()
        .sslSocketFactory(sslSocketFactory, trustAllCerts[0] as X509TrustManager)
        .hostnameVerifier { _, _ -> true }
        .build()

      val baseUrl = "https://192.168.178.200"
      val url = "$baseUrl/v1/messages/${messageList.destination}?story=${story.toQueryParam()}"
      
      // Serialize messageList to send proper payload to the backend
      val payloadBody = org.signal.network.util.JsonUtil.toJson(messageList)
      val body = payloadBody.toRequestBody("application/json".toMediaType())
      val reqBuilder = Request.Builder().url(url).put(body)
      
      val uuid = System.getProperty("parewa_uuid") ?: ""
      val password = System.getProperty("parewa_password") ?: ""
      if (uuid.isNotEmpty()) {
        val basicAuth = okhttp3.Credentials.basic(uuid, password)
        reqBuilder.addHeader("Authorization", basicAuth)
      }
      val request = reqBuilder.build()
      
      client.newCall(request).execute().use { response ->
        if (response.isSuccessful) {
          Log.i("MessageApi", "Parewa MVP: HTTP fallback successful!")
          val mockResponse = SendMessageResponse(false, false)
          NetworkResult.Success(mockResponse)
        } else {
          Log.w("MessageApi", "Parewa MVP: HTTP fallback failed with ${response.code}")
          NetworkResult.StatusCodeError(NonSuccessfulResponseCodeException(response.code, "", null as String?, emptyMap<String, String>()))
        }
      }
    } catch (e: Exception) {
      Log.e("MessageApi", "Parewa MVP: HTTP fallback exception", e)
      NetworkResult.ApplicationError(e)
    }
  }

  /**
   * Sends a common message to multiple recipients using the libsignal-net [UnauthMessagesService].
   */
  fun sendGroupMessage(body: ByteArray, auth: MultiRecipientSendAuthorization, timestamp: Long, online: Boolean, urgent: Boolean): RequestResult<MultiRecipientMessageResponse, MultiRecipientSendFailure> {
    return runBlocking {
      unauthWebSocket.runCatchingWithChatConnection { chatConnection ->
        UnauthMessagesService(chatConnection).sendMultiRecipientMessage(body, timestamp, auth, online, urgent)
      }
    }
  }

  /**
   * Report a message sender and message id as spam.
   *
   * POST /v1/messages/report/[serviceId]/[serverGuid]
   * - 200: Success
   */
  fun reportSpam(serviceId: ServiceId, serverGuid: String, reportingToken: String?): NetworkResult<Unit> {
    val request = WebSocketRequestMessage.post("/v1/messages/report/$serviceId/$serverGuid", SpamTokenMessage(reportingToken))
    return NetworkResult.fromWebSocketRequest(authWebSocket, request)
  }

  private fun Boolean.toQueryParam(): String = if (this) "true" else "false"
}

fun MultiRecipientMessageResponse.unsentTargets(): Set<ServiceId> {
  return unregisteredIds.mapTo(HashSet(unregisteredIds.size)) { ServiceId.fromLibSignal(it) }
}
