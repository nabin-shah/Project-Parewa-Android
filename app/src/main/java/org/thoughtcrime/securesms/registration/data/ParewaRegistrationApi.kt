/*
 * Copyright 2026 Project Parewa
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.thoughtcrime.securesms.registration.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.ConnectionSpec
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import org.signal.core.util.logging.Log
import org.whispersystems.signalservice.internal.util.BlacklistingTrustManager
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

data class ParewaOtpResponse(
  val uuid: String,
  val pni: String,
  val storageCapable: Boolean,
  val reRegistration: Boolean,
  val number: String
)

/**
 * Direct HTTP client for Project Parewa's local backend.
 * Bypasses Signal's complex session-based registration and talks
 * directly to our Node.js auth service endpoints.
 */
object ParewaRegistrationApi {

  private val TAG = Log.tag(ParewaRegistrationApi::class.java)

  private const val BASE_URL = "https://192.168.178.200"
  private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()

  private val httpClient: OkHttpClient by lazy {
    val trustManagers = BlacklistingTrustManager.createTrustAllManager()
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, trustManagers, null)

    OkHttpClient.Builder()
      .sslSocketFactory(sslContext.socketFactory, trustManagers[0] as X509TrustManager)
      .connectionSpecs(listOf(ConnectionSpec.COMPATIBLE_TLS, ConnectionSpec.CLEARTEXT))
      .hostnameVerifier { _, _ -> true }
      .connectTimeout(30, TimeUnit.SECONDS)
      .readTimeout(30, TimeUnit.SECONDS)
      .writeTimeout(30, TimeUnit.SECONDS)
      .build()
  }

  /**
   * Request an OTP to be sent to the given email address.
   * Calls POST /v1/accounts/sms/code with {"email": "..."}
   */
  suspend fun requestOtp(email: String): Result<String> = withContext(Dispatchers.IO) {
    try {
      val jsonBody = JSONObject().apply {
        put("email", email)
      }.toString()

      val request = Request.Builder()
        .url("$BASE_URL/v1/accounts/sms/code")
        .post(jsonBody.toRequestBody(JSON_MEDIA_TYPE))
        .addHeader("Content-Type", "application/json")
        .build()

      Log.d(TAG, "Requesting OTP for email: $email")
      val response = httpClient.newCall(request).execute()

      if (response.isSuccessful) {
        val body = response.body?.string() ?: ""
        Log.i(TAG, "OTP request successful: $body")
        Result.success(body)
      } else {
        val errorBody = response.body?.string() ?: "Unknown error"
        Log.w(TAG, "OTP request failed (${response.code}): $errorBody")
        Result.failure(ParewaRegistrationException("OTP request failed: ${response.code} - $errorBody"))
      }
    } catch (e: Exception) {
      Log.w(TAG, "OTP request exception", e)
      Result.failure(e)
    }
  }

  /**
   * Verify the OTP code for the given email address.
   * Calls POST /v1/accounts/code with {"email": "...", "otp": "..."}
   */
  suspend fun verifyOtp(email: String, code: String): Result<ParewaOtpResponse> = withContext(Dispatchers.IO) {
    try {
      val jsonBody = JSONObject().apply {
        put("email", email)
        put("code", code)
      }.toString()

      val request = Request.Builder()
        .url("$BASE_URL/v1/accounts/code")
        .post(jsonBody.toRequestBody(JSON_MEDIA_TYPE))
        .addHeader("Content-Type", "application/json")
        .build()

      Log.d(TAG, "Verifying OTP for email: $email")
      val response = httpClient.newCall(request).execute()

      if (response.isSuccessful) {
        val body = response.body?.string() ?: "{}"
        Log.i(TAG, "OTP verification successful: $body")
        val json = JSONObject(body)
        val otpResponse = ParewaOtpResponse(
          uuid = json.optString("uuid", java.util.UUID.randomUUID().toString()),
          pni = json.optString("pni", java.util.UUID.randomUUID().toString()),
          storageCapable = json.optBoolean("storageCapable", false),
          reRegistration = json.optBoolean("reRegistration", false),
          number = json.optString("number", email)
        )
        Result.success(otpResponse)
      } else {
        val errorBody = response.body?.string() ?: "Unknown error"
        Log.w(TAG, "OTP verification failed (${response.code}): $errorBody")
        Result.failure(ParewaRegistrationException("OTP verification failed: ${response.code} - $errorBody"))
      }
    } catch (e: Exception) {
      Log.w(TAG, "OTP verification exception", e)
      Result.failure(e)
    }
  }

  /**
   * Generate a deterministic fake E164 phone number from an email address.
   * Uses SHA-256 of the email and takes the first 10 digits prefixed with +1.
   * This keeps each user unique while satisfying Signal's internal phone number validation.
   */
  fun emailToFakeE164(email: String): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val hashBytes = digest.digest(email.lowercase().trim().toByteArray())
    val hashHex = hashBytes.joinToString("") { "%02x".format(it) }

    // Take first 10 numeric characters from the hex digest
    val digits = hashHex.filter { it.isDigit() }.take(10).padEnd(10, '0')
    return "+1$digits"
  }

  /**
   * Check if an email address has valid format.
   */
  fun isValidEmail(email: String): Boolean {
    return android.util.Patterns.EMAIL_ADDRESS.matcher(email).matches()
  }
}

class ParewaRegistrationException(message: String) : Exception(message)
