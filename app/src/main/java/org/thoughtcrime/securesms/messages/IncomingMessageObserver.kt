package org.thoughtcrime.securesms.messages

import android.app.Application
import android.app.Notification
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import androidx.annotation.VisibleForTesting
import androidx.core.app.NotificationCompat
import io.reactivex.rxjava3.disposables.Disposable
import io.reactivex.rxjava3.kotlin.subscribeBy
import io.reactivex.rxjava3.schedulers.Schedulers
import org.signal.core.models.ServiceId
import org.signal.core.util.AppForegroundObserver
import org.signal.core.util.SafeForegroundService
import org.signal.core.util.SleepTimer
import org.signal.core.util.UptimeSleepTimer
import org.signal.core.util.concurrent.SignalExecutors
import org.signal.core.util.logging.Log
import org.signal.storageservice.storage.protos.groups.local.DecryptedGroup
import org.thoughtcrime.securesms.R
import org.thoughtcrime.securesms.crypto.ReentrantSessionLock
import org.thoughtcrime.securesms.database.SignalDatabase
import org.thoughtcrime.securesms.dependencies.AppDependencies
import org.thoughtcrime.securesms.groups.GroupsV2ProcessingLock
import org.thoughtcrime.securesms.groups.v2.processing.GroupsV2StateProcessor
import org.thoughtcrime.securesms.jobmanager.Job
import org.thoughtcrime.securesms.jobmanager.impl.BackoffUtil
import org.thoughtcrime.securesms.jobmanager.impl.NetworkConstraint
import org.thoughtcrime.securesms.jobs.PushProcessMessageErrorJob
import org.thoughtcrime.securesms.jobs.PushProcessMessageJob
import org.thoughtcrime.securesms.jobs.RequestGroupV2InfoJob
import org.thoughtcrime.securesms.keyvalue.SignalStore
import org.thoughtcrime.securesms.keyvalue.isDecisionPending
import org.thoughtcrime.securesms.messages.MessageDecryptor.FollowUpOperation
import org.thoughtcrime.securesms.messages.protocol.BufferedProtocolStore
import org.thoughtcrime.securesms.notifications.NotificationChannels
import org.thoughtcrime.securesms.push.SignalServiceNetworkAccess.Companion.toApplicableSystemHttpProxy
import org.thoughtcrime.securesms.recipients.RecipientId
import org.thoughtcrime.securesms.util.AlarmSleepTimer
import org.thoughtcrime.securesms.util.Environment
import org.thoughtcrime.securesms.util.SignalLocalMetrics
import org.thoughtcrime.securesms.util.SignalTrace
import org.thoughtcrime.securesms.util.TextSecurePreferences
import org.thoughtcrime.securesms.util.asChain
import org.whispersystems.signalservice.api.messages.EnvelopeResponse
import org.whispersystems.signalservice.api.websocket.SignalWebSocket
import org.whispersystems.signalservice.api.websocket.WebSocketConnectionState
import org.whispersystems.signalservice.api.websocket.WebSocketUnavailableException
import org.whispersystems.signalservice.internal.configuration.HttpProxy
import org.whispersystems.signalservice.internal.push.Envelope
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import kotlin.math.round
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import okio.ByteString.Companion.decodeBase64

/**
 * The application-level manager of our incoming message processing.
 *
 * This class is responsible for keeping the authenticated websocket open based on the app's state for incoming messages and
 * observing new inbound messages received over the websocket.
 */
class IncomingMessageObserver(
  private val context: Application,
  private val authWebSocket: SignalWebSocket.AuthenticatedWebSocket,
  private val unauthWebSocket: SignalWebSocket.UnauthenticatedWebSocket
) {

  companion object {
    private val TAG = Log.tag(IncomingMessageObserver::class.java)

    private const val WEB_SOCKET_KEEP_ALIVE_TOKEN = "MessageRetrieval"

    /** How long we wait for the websocket to time out before we try to connect again. */
    private val websocketReadTimeout: Long
      get() = if (censored) 30.seconds.inWholeMilliseconds else 1.minutes.inWholeMilliseconds

    /** How long the websocket is allowed to keep running after the user backgrounds the app. Higher numbers allow us to rely on FCM less. */
    private val maxBackgroundTime: Long
      get() = if (censored) 10.seconds.inWholeMilliseconds else 2.minutes.inWholeMilliseconds

    private val INSTANCE_COUNT = AtomicInteger(0)

    const val FOREGROUND_ID = 313399

    private val censored: Boolean
      get() = AppDependencies.signalServiceNetworkAccess.isCensored()

    /**
     * Stops the foreground service for websocket users.
     */
    @JvmStatic
    fun stopForegroundService(context: Context) {
      SafeForegroundService.stop(context, ForegroundService::class.java)
    }
  }

  private val decryptionDrainedListeners: MutableList<Runnable> = CopyOnWriteArrayList()

  private val lock: ReentrantLock = ReentrantLock()
  private val connectionNecessarySemaphore = Semaphore(0)
  private var previousSystemHttpProxy: HttpProxy? = null
  private val networkConnectionListener = NetworkConnectionListener(
    context = context,
    onNetworkLost = { isNetworkUnavailable ->
      lock.withLock {
        AppDependencies.libsignalNetwork.onNetworkChange()
        if (isNetworkUnavailable()) {
          Log.w(TAG, "Lost network connection. Resetting the drained state.")
          decryptionDrained = false
          authWebSocket.disconnect()
          // TODO [no-more-rest] Move the connection listener to a neutral location so this isn't passed in
          unauthWebSocket.disconnect()
        }
        connectionNecessarySemaphore.release()
      }
    },
    onProxySettingsChanged = { proxyInfo ->
      val systemHttpProxy = proxyInfo.toApplicableSystemHttpProxy()
      if (systemHttpProxy?.host != previousSystemHttpProxy?.host || systemHttpProxy?.port != previousSystemHttpProxy?.port) {
        val networkReset = AppDependencies.onSystemHttpProxyChange(systemHttpProxy)
        if (networkReset) {
          Log.i(TAG, "System proxy configuration changed, network reset.")
        }
      }
      previousSystemHttpProxy = systemHttpProxy
    }
  )

  private val messageContentProcessor = MessageContentProcessor.create(context)

  private var appVisible = false
  private var lastInteractionTime: Long = System.currentTimeMillis()
  private var webSocketStateDisposable = Disposable.disposed()

  @Volatile
  private var terminated = false

  @Volatile
  var decryptionDrained = false
    private set

  init {
    if (INSTANCE_COUNT.incrementAndGet() != 1) {
      throw AssertionError("Multiple observers!")
    }

    MessageRetrievalThread().start()

    val registered = SignalStore.account.isRegistered && !TextSecurePreferences.isUnauthorizedReceived(context)
    if (registered && (!SignalStore.account.fcmEnabled || SignalStore.settings.forceWebsocketMode.isEnabled)) {
      SignalExecutors.UNBOUNDED.execute {
        if (!SafeForegroundService.start(context, ForegroundService::class.java)) {
          Log.w(TAG, "Unable to start foreground service for websocket!")
        }
      }
    }

    AppForegroundObserver.addListener(object : AppForegroundObserver.Listener {
      override fun onForeground() {
        SignalExecutors.BOUNDED.execute { onAppForegrounded() }
      }

      override fun onBackground() {
        SignalExecutors.BOUNDED.execute { onAppBackgrounded() }
      }
    })

    networkConnectionListener.register()

    webSocketStateDisposable = authWebSocket
      .state
      .observeOn(Schedulers.computation())
      .subscribeBy {
        if (it == WebSocketConnectionState.CONNECTED) {
          lock.withLock {
            connectionNecessarySemaphore.release()
          }
        }
      }

    authWebSocket.addKeepAliveChangeListener {
      SignalExecutors.BOUNDED.execute {
        lock.withLock {
          connectionNecessarySemaphore.release()
        }
      }
    }
  }

  fun notifyRegistrationStateChanged() {
    connectionNecessarySemaphore.release()
  }

  fun notifyRestoreDecisionMade() {
    Log.i(TAG, "Restore decision made, can restart network and process messages")
    AppDependencies.resetNetwork()
  }

  fun addDecryptionDrainedListener(listener: Runnable) {
    decryptionDrainedListeners.add(listener)
    if (decryptionDrained) {
      listener.run()
    }
  }

  fun removeDecryptionDrainedListener(listener: Runnable) {
    decryptionDrainedListeners.remove(listener)
  }

  private fun onAppForegrounded() {
    lock.withLock {
      appVisible = true
      BackgroundService.start(context)
      connectionNecessarySemaphore.release()
    }
  }

  private fun onAppBackgrounded() {
    lock.withLock {
      appVisible = false
      lastInteractionTime = System.currentTimeMillis()
      connectionNecessarySemaphore.release()
    }
  }

  private fun isConnectionNecessary(): Boolean {
    val timeIdle: Long
    val appVisibleSnapshot: Boolean

    lock.withLock {
      appVisibleSnapshot = appVisible
      timeIdle = if (appVisibleSnapshot) 0 else System.currentTimeMillis() - lastInteractionTime
    }

    val registered = SignalStore.account.isRegistered
    val unauthorizedReceived = TextSecurePreferences.isUnauthorizedReceived(context)
    val fcmEnabled = SignalStore.account.fcmEnabled
    val hasNetwork = NetworkConstraint.isMet(context)
    val hasProxy = SignalStore.proxy.isProxyEnabled
    val forceWebsocket = SignalStore.settings.forceWebsocketMode.isEnabled
    val websocketAlreadyOpen = isConnectionAvailable()

    val lastInteractionString = if (appVisibleSnapshot) "N/A" else timeIdle.toString() + " ms (" + (if (timeIdle < maxBackgroundTime) "within limit" else "over limit") + ")"
    val conclusion = registered &&
      !unauthorizedReceived &&
      (appVisibleSnapshot || timeIdle < maxBackgroundTime || !fcmEnabled || forceWebsocket) &&
      hasNetwork

    val needsConnectionString = if (conclusion) "Needs Connection" else "Does Not Need Connection"

    Log.d(
      TAG,
      "[$needsConnectionString] Network: $hasNetwork, Foreground: $appVisibleSnapshot, Time Since Last Interaction: $lastInteractionString, FCM: $fcmEnabled, WS Open or Keep-alives: $websocketAlreadyOpen, Registered: $registered, Unauthorized: $unauthorizedReceived, Proxy: $hasProxy, Force websocket: $forceWebsocket"
    )

    return conclusion
  }

  private fun isConnectionAvailable(): Boolean {
    return !TextSecurePreferences.isUnauthorizedReceived(context) && SignalStore.account.isRegistered && (authWebSocket.stateSnapshot == WebSocketConnectionState.CONNECTED || (authWebSocket.shouldSendKeepAlives() && NetworkConstraint.isMet(context)))
  }

  private fun waitForConnectionNecessary() {
    try {
      connectionNecessarySemaphore.drainPermits()
      while (!isConnectionNecessary() && !isConnectionAvailable()) {
        val numberDrained = connectionNecessarySemaphore.drainPermits()
        if (numberDrained == 0) {
          connectionNecessarySemaphore.acquire()
        }
      }
    } catch (e: InterruptedException) {
      throw AssertionError(e)
    }
  }

  fun terminate() {
    Log.w(TAG, "Termination! ${this.hashCode()}", Throwable())
    INSTANCE_COUNT.decrementAndGet()
    networkConnectionListener.unregister()
    webSocketStateDisposable.dispose()
    terminated = true
    authWebSocket.disconnect()
  }

  @VisibleForTesting
  fun processEnvelope(bufferedProtocolStore: BufferedProtocolStore, envelope: Envelope, serverDeliveredTimestamp: Long, batchCache: BatchCache): ProcessingResult? {
    return when (envelope.type) {
      Envelope.Type.SERVER_DELIVERY_RECEIPT -> {
        processReceipt(envelope)
        null
      }

      Envelope.Type.PREKEY_MESSAGE,
      Envelope.Type.DOUBLE_RATCHET,
      Envelope.Type.UNIDENTIFIED_SENDER,
      Envelope.Type.PLAINTEXT_CONTENT -> {
        SignalTrace.beginSection("IncomingMessageObserver#processMessage")
        val result = processMessage(bufferedProtocolStore, envelope, serverDeliveredTimestamp, batchCache)
        SignalTrace.endSection()
        result
      }

      else -> {
        Log.w(TAG, "Received envelope of unknown type: " + envelope.type)
        null
      }
    }
  }

  private fun processMessage(bufferedProtocolStore: BufferedProtocolStore, envelope: Envelope, serverDeliveredTimestamp: Long, batchCache: BatchCache): ProcessingResult {
    val localReceiveMetric = SignalLocalMetrics.MessageReceive.start()
    SignalTrace.beginSection("IncomingMessageObserver#decryptMessage")
    val result = MessageDecryptor.decrypt(context, bufferedProtocolStore, envelope, serverDeliveredTimestamp)
    SignalTrace.endSection()
    localReceiveMetric.onEnvelopeDecrypted()

    var isNetworkResetRequired = false

    SignalLocalMetrics.MessageLatency.onMessageReceived(envelope.serverTimestamp!!, serverDeliveredTimestamp, envelope.urgent!!)
    when (result) {
      is MessageDecryptor.Result.Success -> {
        val job = PushProcessMessageJob.processOrDefer(messageContentProcessor, result, localReceiveMetric, batchCache)
        isNetworkResetRequired = isNetworkResetRequired(result, bufferedProtocolStore.pni)
        if (job != null) {
          return ProcessingResult(
            followUpOperations = result.followUpOperations + FollowUpOperation { job.asChain() },
            isNetworkResetRequired = isNetworkResetRequired
          )
        }
      }

      is MessageDecryptor.Result.Error -> {
        return ProcessingResult(
          result.followUpOperations + FollowUpOperation {
            val jobs = mutableListOf<Job>()

            if (result.errorMetadata.groupMasterKey != null) {
              val groupId = result.errorMetadata.groupId!!
              if (!SignalDatabase.groups.getGroup(groupId).isPresent) {
                Log.w(TAG, "Decryption error in group, but group not found. Creating placeholder for groupId: $groupId")
                SignalDatabase.groups.create(
                  groupMasterKey = result.errorMetadata.groupMasterKey!!,
                  groupState = DecryptedGroup(revision = GroupsV2StateProcessor.RESTORE_PLACEHOLDER_REVISION),
                  groupSendEndorsements = null
                )
                jobs += RequestGroupV2InfoJob(groupId)
              }
            }

            jobs += PushProcessMessageErrorJob(
              result.toMessageState(),
              result.errorMetadata.toExceptionMetadata(),
              result.envelope.clientTimestamp!!
            )

            AppDependencies.jobManager.startChain(jobs)
          }
        )
      }

      is MessageDecryptor.Result.Ignore -> {
        // No action needed
      }

      else -> {
        throw AssertionError("Unexpected result! ${result.javaClass.simpleName}")
      }
    }

    return ProcessingResult(
      followUpOperations = result.followUpOperations,
      isNetworkResetRequired = isNetworkResetRequired
    )
  }

  /**
   * True iff this envelope's PniChangeNumber sync actually changed our PNI within this batch.
   * Comparing the batch-start PNI against the current value makes the check idempotent — a
   * redelivered envelope finds the PNI already applied and won't re-trigger a websocket reset.
   */
  private fun isNetworkResetRequired(result: MessageDecryptor.Result.Success, pniAtBatchStart: ServiceId.PNI): Boolean {
    return result.content.syncMessage?.pniChangeNumber != null && SignalStore.account.pni != pniAtBatchStart
  }

  private fun processReceipt(envelope: Envelope) {
    val serviceId = ServiceId.parseOrNull(envelope.sourceServiceId, envelope.sourceServiceIdBinary)
    if (serviceId == null) {
      Log.w(TAG, "Invalid envelope sourceServiceId!")
      return
    }

    val senderId = RecipientId.from(serviceId)

    Log.i(TAG, "Received server receipt. Sender: $senderId, Device: ${envelope.sourceDeviceId}, Timestamp: ${envelope.clientTimestamp}")
    SignalDatabase.messages.incrementDeliveryReceiptCount(envelope.clientTimestamp!!, senderId, System.currentTimeMillis())
    SignalDatabase.messageLog.deleteEntryForRecipient(envelope.clientTimestamp!!, senderId, envelope.sourceDeviceId!!)
  }

  private fun MessageDecryptor.Result.toMessageState(): MessageState {
    return when (this) {
      is MessageDecryptor.Result.DecryptionError -> MessageState.DECRYPTION_ERROR
      is MessageDecryptor.Result.Ignore -> MessageState.NOOP
      is MessageDecryptor.Result.InvalidVersion -> MessageState.INVALID_VERSION
      is MessageDecryptor.Result.LegacyMessage -> MessageState.LEGACY_MESSAGE
      is MessageDecryptor.Result.Success -> MessageState.DECRYPTED_OK
      is MessageDecryptor.Result.UnsupportedDataMessage -> MessageState.UNSUPPORTED_DATA_MESSAGE
    }
  }

  private fun MessageDecryptor.ErrorMetadata.toExceptionMetadata(): ExceptionMetadata {
    return ExceptionMetadata(
      this.sender,
      this.senderDevice,
      this.groupId
    )
  }

  private inner class MessageRetrievalThread : Thread("MessageRetrievalService"), Thread.UncaughtExceptionHandler {

    private var sleepTimer: SleepTimer
    private val canProcessMessages: Boolean

    init {
      Log.i(TAG, "Initializing! (${this.hashCode()})")
      uncaughtExceptionHandler = this

      sleepTimer = if (!SignalStore.account.fcmEnabled || SignalStore.settings.forceWebsocketMode.isEnabled) AlarmSleepTimer(context) else UptimeSleepTimer()

      canProcessMessages = !SignalStore.registration.restoreDecisionState.isDecisionPending
    }

    override fun run() {
      // Parewa MVP: HTTP Polling instead of Signal's WebSocket infrastructure.
      // We poll GET /v1/messages every 4 seconds when the app is foregrounded.
      // Messages are stored in Redis by PUT /v1/messages/:dest and fetched here.
      Log.i(TAG, "Parewa MVP: Starting HTTP polling loop for message retrieval.")

      decryptionDrained = true
      for (listener in decryptionDrainedListeners.toList()) {
        listener.run()
      }

      val pollIntervalMs = 4000L
      val baseUrl = "https://192.168.178.200"

      // Build a trust-all OkHttpClient for self-signed certs
      val trustAllCerts = arrayOf<javax.net.ssl.TrustManager>(object : javax.net.ssl.X509TrustManager {
        override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
      })
      val sslContext = javax.net.ssl.SSLContext.getInstance("SSL")
      sslContext.init(null, trustAllCerts, java.security.SecureRandom())

      val pollClient = okhttp3.OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, trustAllCerts[0] as javax.net.ssl.X509TrustManager)
        .hostnameVerifier { _, _ -> true }
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

      while (!terminated) {
        try {
          // Only poll when we should be connected (registered + foreground or within background window)
          if (!isConnectionNecessary()) {
            Log.d(TAG, "Parewa: Connection not necessary, sleeping...")
            Thread.sleep(pollIntervalMs * 2)
            continue
          }

          val aci = SignalStore.account.aci?.toString()
          val password = SignalStore.account.servicePassword
          if (aci == null || password == null) {
            Log.w(TAG, "Parewa: No ACI or service password set, skipping poll cycle.")
            Thread.sleep(pollIntervalMs)
            continue
          }

          // Build Basic Auth header: base64("uuid:password")
          val credentials = android.util.Base64.encodeToString(
            "$aci:$password".toByteArray(Charsets.UTF_8),
            android.util.Base64.NO_WRAP
          )

          val request = okhttp3.Request.Builder()
            .url("$baseUrl/v1/messages")
            .get()
            .addHeader("Authorization", "Basic $credentials")
            .build()

          pollClient.newCall(request).execute().use { response ->
            if (response.isSuccessful) {
              val body = response.body?.string() ?: "{}"
              val json = org.json.JSONObject(body)
              val messagesArray = json.optJSONArray("messages")

              if (messagesArray != null && messagesArray.length() > 0) {
                Log.i(TAG, "Parewa: Received ${messagesArray.length()} offline message(s)!")
                val batch = mutableListOf<EnvelopeResponse>()

                for (i in 0 until messagesArray.length()) {
                  val msgObj = messagesArray.getJSONObject(i)
                  Log.d(TAG, "Parewa: Processing message $i")
                  try {
                    val envelopeBuilder = Envelope.Builder()

                    if (msgObj.has("type")) envelopeBuilder.type(Envelope.Type.fromValue(msgObj.getInt("type")))
                    if (msgObj.has("sourceServiceId")) envelopeBuilder.sourceServiceId(msgObj.getString("sourceServiceId"))
                    if (msgObj.has("sourceDeviceId")) envelopeBuilder.sourceDeviceId(msgObj.getInt("sourceDeviceId"))
                    if (msgObj.has("destinationServiceId")) envelopeBuilder.destinationServiceId(msgObj.getString("destinationServiceId"))
                    if (msgObj.has("clientTimestamp")) envelopeBuilder.clientTimestamp(msgObj.getLong("clientTimestamp"))
                    if (msgObj.has("content")) envelopeBuilder.content(msgObj.getString("content").let { it.decodeBase64() })
                    if (msgObj.has("serverGuid")) envelopeBuilder.serverGuid(msgObj.getString("serverGuid"))
                    if (msgObj.has("serverTimestamp")) envelopeBuilder.serverTimestamp(msgObj.getLong("serverTimestamp"))
                    if (msgObj.has("ephemeral")) envelopeBuilder.ephemeral(msgObj.getBoolean("ephemeral"))
                    if (msgObj.has("urgent")) envelopeBuilder.urgent(msgObj.getBoolean("urgent"))
                    if (msgObj.has("updatedPni")) envelopeBuilder.updatedPni(msgObj.getString("updatedPni"))
                    if (msgObj.has("story")) envelopeBuilder.story(msgObj.getBoolean("story"))
                    if (msgObj.has("report_spam_token")) envelopeBuilder.report_spam_token(msgObj.getString("report_spam_token").let { it.decodeBase64() })
                    if (msgObj.has("sourceServiceIdBinary")) envelopeBuilder.sourceServiceIdBinary(msgObj.getString("sourceServiceIdBinary").let { it.decodeBase64() })
                    if (msgObj.has("destinationServiceIdBinary")) envelopeBuilder.destinationServiceIdBinary(msgObj.getString("destinationServiceIdBinary").let { it.decodeBase64() })
                    if (msgObj.has("serverGuidBinary")) envelopeBuilder.serverGuidBinary(msgObj.getString("serverGuidBinary").let { it.decodeBase64() })
                    if (msgObj.has("updatedPniBinary")) envelopeBuilder.updatedPniBinary(msgObj.getString("updatedPniBinary").let { it.decodeBase64() })

                    val envelope = envelopeBuilder.build()
                    val serverTimestamp = envelope.serverTimestamp ?: System.currentTimeMillis()
                    val dummyRequest = org.signal.network.websocket.WebSocketRequestMessage.Builder().build()
                    
                    batch.add(EnvelopeResponse(envelope, serverTimestamp, dummyRequest))
                  } catch (e: Exception) {
                    Log.w(TAG, "Parewa: Failed to parse envelope JSON", e)
                  }
                }

                if (batch.isNotEmpty()) {
                  Log.i(TAG, "Parewa: Submitting batch of ${batch.size} messages to transaction processor")
                  if (!processBatchInTransaction(batch)) {
                    processMessagesIndividually(batch)
                  }
                }
              }
            } else {
              Log.w(TAG, "Parewa: Poll GET /v1/messages failed with HTTP ${response.code}")
            }
          }
        } catch (e: InterruptedException) {
          Log.w(TAG, "Parewa: Polling thread interrupted.", e)
          break
        } catch (e: Exception) {
          Log.w(TAG, "Parewa: Error during message poll cycle.", e)
        }

        try {
          Thread.sleep(pollIntervalMs)
        } catch (e: InterruptedException) {
          Log.w(TAG, "Parewa: Sleep interrupted.", e)
          break
        }
      }

      // Cleanup when loop exits
      if (!appVisible) {
        BackgroundService.stop(context)
      }

      Log.w(TAG, "Parewa: Polling thread terminated! (${this.hashCode()})")
    }

    /**
     * Attempts to process the entire batch in a single transaction for performance.
     *
     * @return true if the transaction committed, false if it the batch was rolled back.
     */
    private fun processBatchInTransaction(batch: List<EnvelopeResponse>): Boolean {
      val allFollowUpOperations = mutableListOf<FollowUpOperation>()
      val bufferedStore = BufferedProtocolStore.create()
      val batchCache = ReusedBatchCache()
      var processedCount = 0
      var networkResetRequired = false

      val committed = SignalDatabase.tryRunInTransaction {
        for (response in batch) {
          SignalTrace.beginSection("IncomingMessageObserver#perMessageTransaction")
          val result = processEnvelope(bufferedStore, response.envelope, response.serverDeliveredTimestamp, batchCache)
          bufferedStore.flushToDisk()
          SignalTrace.endSection()

          if (result?.followUpOperations?.isNotEmpty() == true) {
            allFollowUpOperations += result.followUpOperations
          }

          processedCount++

          if (result?.isNetworkResetRequired == true) {
            networkResetRequired = true
            Log.w(TAG, "Self identity changed mid-batch after envelope $processedCount of ${batch.size}. Committing what we have; the remainder will be redelivered to the new connection.")
            break
          }
        }
      }

      if (committed) {
        batchCache.flushAndClear()

        if (allFollowUpOperations.isNotEmpty()) {
          Log.d(TAG, "Running ${allFollowUpOperations.size} follow-up operations...")
          val jobs = allFollowUpOperations.mapNotNull { it.run() }
          AppDependencies.jobManager.addAllChains(jobs)
        }

        for (i in 0 until processedCount) {
          sendAckSafely(batch[i], i, batch.size)
        }

        if (networkResetRequired) {
          AppDependencies.resetNetwork()
          AppDependencies.startNetwork()
        }
      }

      return committed
    }

    /**
     * If something prevented us from processing the entire batch in a single transaction, we process each message individually.
     */
    private fun processMessagesIndividually(batch: List<EnvelopeResponse>) {
      val bufferedStore = BufferedProtocolStore.create()
      val batchCache = ReusedBatchCache()

      for ((index, response) in batch.withIndex()) {
        SignalTrace.beginSection("IncomingMessageObserver#perMessageTransaction")
        val results = SignalDatabase.runInTransaction {
          val result = processEnvelope(bufferedStore, response.envelope, response.serverDeliveredTimestamp, batchCache)
          bufferedStore.flushToDisk()
          result
        }
        SignalTrace.endSection()

        if (results?.followUpOperations?.isNotEmpty() == true) {
          val jobs = results.followUpOperations.mapNotNull { it.run() }
          AppDependencies.jobManager.addAllChains(jobs)
        }

        sendAckSafely(response, index, batch.size)

        if (results?.isNetworkResetRequired == true) {
          Log.w(TAG, "Self identity changed mid-batch after envelope ${index + 1} of ${batch.size}. Stopping individual processing; the remainder will be redelivered to the new connection.")
          AppDependencies.resetNetwork()
          AppDependencies.startNetwork()
          break
        }
      }

      batchCache.flushAndClear()
    }

    /**
     * Best-effort ack. Failures just mean the server will redeliver — and for a redelivered
     * PniChangeNumber sync, [isNetworkResetRequired] sees the PNI is already applied and won't
     * re-trigger a reset, so we don't loop.
     */
    private fun sendAckSafely(response: EnvelopeResponse, index: Int, size: Int) {
      try {
        authWebSocket.sendAck(response)
      } catch (e: Exception) {
        Log.w(TAG, "Failed to send ack for envelope $index of $size. The server will redeliver.", e)
      }
    }

    override fun uncaughtException(t: Thread, e: Throwable) {
      Log.w(TAG, "Uncaught exception in message thread!", e)
    }
  }

  /**
   * Keeps the process alive for websocket users.
   */
  class ForegroundService : SafeForegroundService() {
    override val tag: String = TAG
    override val notificationId: Int = FOREGROUND_ID

    override fun getForegroundNotification(intent: Intent): Notification {
      return NotificationCompat.Builder(applicationContext, NotificationChannels.getInstance().BACKGROUND)
        .setContentTitle(applicationContext.getString(R.string.MessageRetrievalService_signal))
        .setContentText(applicationContext.getString(R.string.MessageRetrievalService_background_connection_enabled))
        .setPriority(NotificationCompat.PRIORITY_MIN)
        .setWhen(0)
        .setSmallIcon(R.drawable.ic_signal_background_connection)
        .build()
    }
  }

  /**
   * A service that exists just to encourage the system to keep our process alive a little longer.
   */
  class BackgroundService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
      Log.d(TAG, "Background service started.")
      return START_STICKY
    }

    override fun onDestroy() {
      Log.d(TAG, "Background service destroyed.")
    }

    companion object {
      fun start(context: Context) {
        try {
          context.startService(Intent(context, BackgroundService::class.java))
        } catch (e: Exception) {
          Log.w(TAG, "Failed to start background service.", e)
        }
      }

      fun stop(context: Context) {
        context.stopService(Intent(context, BackgroundService::class.java))
      }
    }
  }

  data class ProcessingResult(
    val followUpOperations: List<FollowUpOperation>,
    val isNetworkResetRequired: Boolean = false
  )
}
