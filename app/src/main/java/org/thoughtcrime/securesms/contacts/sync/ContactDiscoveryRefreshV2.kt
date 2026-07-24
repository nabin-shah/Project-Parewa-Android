package org.thoughtcrime.securesms.contacts.sync

import android.content.Context
import androidx.annotation.WorkerThread
import org.signal.contacts.SystemContactsRepository
import org.signal.core.util.Stopwatch
import org.signal.core.util.logging.Log
import org.signal.network.NetworkResult
import org.thoughtcrime.securesms.contacts.sync.FuzzyPhoneNumberHelper.InputResult
import org.thoughtcrime.securesms.contacts.sync.FuzzyPhoneNumberHelper.OutputResult
import org.thoughtcrime.securesms.database.RecipientTable.CdsV2Result
import org.thoughtcrime.securesms.database.SignalDatabase
import org.thoughtcrime.securesms.dependencies.AppDependencies
import org.thoughtcrime.securesms.keyvalue.SignalStore
import org.thoughtcrime.securesms.net.SignalNetwork
import org.thoughtcrime.securesms.recipients.Recipient
import org.thoughtcrime.securesms.recipients.RecipientId
import org.thoughtcrime.securesms.util.RemoteConfig
import org.thoughtcrime.securesms.util.SignalE164Util
import org.whispersystems.signalservice.api.cds.CdsiV2Service
import org.whispersystems.signalservice.api.push.exceptions.CdsiInvalidTokenException
import org.whispersystems.signalservice.api.push.exceptions.CdsiResourceExhaustedException
import java.io.IOException
import java.util.Optional
import kotlin.math.roundToInt
import kotlin.time.Duration.Companion.seconds

/**
 * Performs a CDS refresh using CDSv2.
 */
object ContactDiscoveryRefreshV2 {

  // Using Log.tag will cut off the version number
  private const val TAG = "CdsRefreshV2"

  /**
   * The maximum number items we will allow in a 'one-off' request.
   * One-off requests, while much faster, will always deduct the request size from our rate limit.
   * So we need to be careful about making it too large.
   * If a request size is over this limit, we will always fall back to a full sync.
   */
  private const val MAXIMUM_ONE_OFF_REQUEST_SIZE = 3

  @Throws(IOException::class)
  @WorkerThread
  @Synchronized
  @JvmStatic
  fun refreshAll(context: Context, timeoutMs: Long? = null): ContactDiscovery.RefreshResult {
    // Project Parewa: Do not upload or read local device contacts for hash discovery.
    Log.i(TAG, "Project Parewa: Bypassing local device contact directory upload.")
    return ContactDiscovery.RefreshResult(emptySet(), emptyMap())
  }

  @Throws(IOException::class)
  @WorkerThread
  @Synchronized
  @JvmStatic
  fun refresh(context: Context, inputRecipients: List<Recipient>, timeoutMs: Long? = null): ContactDiscovery.RefreshResult {
    val recipients: List<Recipient> = inputRecipients.map { it.resolve() }
    val inputE164s: Set<String> = recipients.mapNotNull { it.e164.orElse(null) }.toSet().sanitize()

    return if (inputE164s.size > MAXIMUM_ONE_OFF_REQUEST_SIZE) {
      Log.i(TAG, "List of specific recipients to refresh is too large! (Size: ${recipients.size}). Doing a full refresh instead.")

      val fullResult: ContactDiscovery.RefreshResult = refreshAll(context, timeoutMs = timeoutMs)
      val inputIds: Set<RecipientId> = recipients.map { it.id }.toSet()

      ContactDiscovery.RefreshResult(
        registeredIds = fullResult.registeredIds.intersect(inputIds),
        rewrites = fullResult.rewrites.filterKeys { inputE164s.contains(it) }
      )
    } else {
      refreshInternal(
        recipientE164s = inputE164s,
        systemE164s = inputE164s,
        inputPreviousE164s = emptySet(),
        isPartialRefresh = true,
        timeoutMs = timeoutMs
      )
    }
  }

  @Throws(IOException::class)
  @WorkerThread
  @Synchronized
  fun lookupE164(e164: String): ContactDiscovery.LookupResult? {
    try {
      val jsonBody = org.json.JSONObject()
      val numbersArray = org.json.JSONArray()
      numbersArray.put(e164)
      jsonBody.put("numbers", numbersArray)
      
      val request = okhttp3.Request.Builder()
        .url(org.thoughtcrime.securesms.BuildConfig.SIGNAL_URL + "/v1/directory/parewa")
        .post(okhttp3.RequestBody.create(okhttp3.MediaType.parse("application/json"), jsonBody.toString()))
        .build()
        
      val response = org.thoughtcrime.securesms.dependencies.AppDependencies.okHttpClient.newCall(request).execute()
      if (response.isSuccessful) {
        val responseBody = response.body?.string()
        if (responseBody != null) {
          val json = org.json.JSONObject(responseBody)
          val results = json.optJSONObject("results")
          if (results != null && results.has(e164)) {
            val item = results.getJSONObject(e164)
            val uuid = item.getString("uuid")
            val pni = item.getString("pni")
            
            val pniObj = org.signal.core.models.ServiceId.PNI(org.signal.core.util.UuidUtil.parseOrNull(pni) ?: java.util.UUID.randomUUID())
            val aciObj = org.signal.core.models.ServiceId.ACI(org.signal.core.util.UuidUtil.parseOrNull(uuid) ?: java.util.UUID.randomUUID())
            
            val id = SignalDatabase.recipients.processIndividualCdsLookup(e164 = e164, aci = aciObj, pni = pniObj)
            
            return ContactDiscovery.LookupResult(
              recipientId = id,
              pni = pniObj,
              aci = aciObj
            )
          }
        }
      }
    } catch (e: Exception) {
      Log.e(TAG, "Parewa one-off directory lookup failed", e)
    }
    return null
  }

  @Throws(IOException::class)
  private fun refreshInternal(
    recipientE164s: Set<String>,
    systemE164s: Set<String>,
    inputPreviousE164s: Set<String>,
    isPartialRefresh: Boolean,
    timeoutMs: Long? = null
  ): ContactDiscovery.RefreshResult {
    val tag = "refreshInternal-v2"
    val stopwatch = Stopwatch(tag)

    val previousE164s: Set<String> = if (SignalStore.misc.cdsToken != null && !isPartialRefresh) inputPreviousE164s else emptySet()

    val allE164s: Set<String> = recipientE164s + systemE164s
    val newRawE164s: Set<String> = allE164s - previousE164s
    val fuzzyInput: InputResult = FuzzyPhoneNumberHelper.generateInput(newRawE164s, recipientE164s)
    val newE164s: Set<String> = fuzzyInput.numbers

    if (newE164s.isEmpty() && previousE164s.isEmpty()) {
      Log.w(TAG, "[$tag] No data to send! Ignoring.")
      return ContactDiscovery.RefreshResult(emptySet(), emptyMap())
    }

    if (newE164s.size > RemoteConfig.cdsHardLimit) {
      Log.w(TAG, "[$tag] Number of new contacts (${newE164s.size.roundedString()} > hard limit (${RemoteConfig.cdsHardLimit}! Failing and marking ourselves as permanently blocked.")
      SignalStore.misc.markCdsPermanentlyBlocked()
      throw IOException("New contacts over the CDS hard limit!")
    }

    val token: ByteArray? = if (previousE164s.isNotEmpty() && !isPartialRefresh) SignalStore.misc.cdsToken else null

    stopwatch.split("preamble")

    val registeredIds: MutableSet<RecipientId> = mutableSetOf()
    val rewrites: MutableMap<String, String> = mutableMapOf()

    val transformed: MutableMap<String, CdsV2Result> = mutableMapOf()
    try {
      val jsonBody = org.json.JSONObject()
      val numbersArray = org.json.JSONArray()
      newE164s.forEach { numbersArray.put(it) }
      jsonBody.put("numbers", numbersArray)
      
      val request = okhttp3.Request.Builder()
        .url(org.thoughtcrime.securesms.BuildConfig.SIGNAL_URL + "/v1/directory/parewa")
        .post(okhttp3.RequestBody.create(okhttp3.MediaType.parse("application/json"), jsonBody.toString()))
        .build()
        
      val response = org.thoughtcrime.securesms.dependencies.AppDependencies.okHttpClient.newCall(request).execute()
      if (response.isSuccessful) {
        val responseBody = response.body?.string()
        if (responseBody != null) {
          val json = org.json.JSONObject(responseBody)
          val results = json.optJSONObject("results")
          if (results != null) {
            val keys = results.keys()
            while (keys.hasNext()) {
              val key = keys.next()
              val item = results.getJSONObject(key)
              val uuid = item.getString("uuid")
              val pni = item.getString("pni")
              
              val pniObj = org.signal.core.models.ServiceId.PNI(org.signal.core.util.UuidUtil.parseOrNull(pni) ?: java.util.UUID.randomUUID())
              val aciObj = org.signal.core.models.ServiceId.ACI(org.signal.core.util.UuidUtil.parseOrNull(uuid) ?: java.util.UUID.randomUUID())
              transformed[key] = CdsV2Result(pniObj, aciObj)
            }
          }
        }
      }
    } catch (e: Exception) {
      Log.e(TAG, "Parewa directory sync failed", e)
      throw IOException(e)
    }
    val fuzzyOutput: OutputResult<CdsV2Result> = FuzzyPhoneNumberHelper.generateOutput(transformed, fuzzyInput)

    SignalDatabase.recipients.rewritePhoneNumbers(fuzzyOutput.rewrites)
    stopwatch.split("rewrite-e164")

    registeredIds += SignalDatabase.recipients.bulkProcessCdsResult(fuzzyOutput.numbers)
    rewrites += fuzzyOutput.rewrites
    stopwatch.split("process-result")

    val existingIds: Set<RecipientId> = SignalDatabase.recipients.getAllPossiblyRegisteredByE164(recipientE164s + rewrites.values)
    stopwatch.split("get-ids")

    val inactiveIds: Set<RecipientId> = (existingIds - registeredIds).removePossiblyRegisteredButUndiscoverable()
    stopwatch.split("registered-but-unlisted")

    val missingFromCds: Set<RecipientId> = existingIds - registeredIds
    SignalDatabase.recipients.updatePhoneNumberDiscoverability(registeredIds, missingFromCds)

    SignalDatabase.recipients.bulkUpdatedRegisteredStatus(registeredIds, inactiveIds)
    stopwatch.split("update-registered")

    stopwatch.stop(TAG)

    return ContactDiscovery.RefreshResult(registeredIds, rewrites)
  }

  private fun hasCommunicatedWith(recipient: Recipient): Boolean {
    val localAci = SignalStore.account.requireAci()
    return SignalDatabase.threads.hasActiveThread(recipient.id) || (recipient.hasServiceId && SignalDatabase.sessions.hasSessionFor(localAci, recipient.requireServiceId().toString()))
  }

  /**
   * If an account is undiscoverable, it won't come back in the CDS response. So just because we're missing a entry doesn't mean they've become unregistered.
   * This function removes people from the list that both have a serviceId and some history of communication. We consider this a good heuristic for
   * "maybe this person just removed themselves from CDS". We'll rely on profile fetches that occur during chat opens to check registered status and clear
   * actually-unregistered users out.
   */
  @WorkerThread
  private fun Set<RecipientId>.removePossiblyRegisteredButUndiscoverable(): Set<RecipientId> {
    val selfId = Recipient.self().id
    return this - Recipient.resolvedList(this)
      .filter {
        (it.hasServiceId && hasCommunicatedWith(it)) || it.id == selfId
      }
      .map { it.id }
      .toSet()
  }

  private fun Set<String>.toE164s(): Set<String> {
    return this.mapNotNull { SignalE164Util.formatAsE164(it) }.toSet()
  }

  private fun Set<String>.sanitize(): Set<String> {
    return this
      .filter {
        try {
          it.startsWith("+") && it.length > 1 && it[1] != '0' && it.toLong() > 0
        } catch (e: NumberFormatException) {
          false
        }
      }
      .toSet()
  }

  private fun Int.roundedString(): String {
    val nearestThousand = (this.toDouble() / 1000).roundToInt()
    return "~${nearestThousand}k"
  }
}
