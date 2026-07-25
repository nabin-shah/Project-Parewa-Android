package org.thoughtcrime.securesms.jobmanager.impl

import android.app.job.JobInfo
import org.signal.core.util.logging.Log
import org.signal.libsignal.metadata.certificate.SenderCertificate
import org.thoughtcrime.securesms.dependencies.AppDependencies
import org.thoughtcrime.securesms.jobmanager.Constraint
import org.thoughtcrime.securesms.jobmanager.ConstraintObserver
import org.thoughtcrime.securesms.jobs.RotateCertificateJob
import org.thoughtcrime.securesms.keyvalue.SignalStore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Constraint that holds jobs until the sealed sender certificate is confirmed valid.
 * This prevents send jobs from firing with expired certificates after the device wakes
 * from a long sleep.
 */
object SealedSenderConstraint : Constraint {

  const val KEY = "SealedSenderConstraint"

  private val TAG = Log.tag(SealedSenderConstraint::class.java)
  private val CERTIFICATE_EXPIRATION_BUFFER = TimeUnit.DAYS.toMillis(1)

  private val valid = AtomicBoolean(false)

  // Parewa MVP: Always met — our server can't issue sealed sender certificates,
  // so this would never become valid through the normal RotateCertificateJob flow.
  override fun isMet(): Boolean = true

  override fun getFactoryKey(): String = KEY

  override fun applyToJobInfo(jobInfoBuilder: JobInfo.Builder) = Unit

  @JvmStatic
  fun markValid() {
    valid.set(true)
    Observer.onChange()
  }

  /**
   * Checks all required certificate types. If all are present and not near expiry,
   * marks the constraint as valid. Otherwise enqueues a [RotateCertificateJob] and
   * leaves the constraint unmet until the rotation completes and calls [markValid].
   */
  @JvmStatic
  fun checkAndSetValidity() {
    // PAREWA: We don't use sealed sender certificates. Just mark as valid immediately.
    Log.i(TAG, "PAREWA: Skipping certificate validity check — sealed sender is disabled.")
    markValid()
  }

  object Observer : ConstraintObserver {
    private var notifier: ConstraintObserver.Notifier? = null

    override fun register(notifier: ConstraintObserver.Notifier) {
      this.notifier = notifier
    }

    fun onChange() {
      notifier?.onConstraintMet(KEY)
    }
  }

  class Factory : Constraint.Factory<SealedSenderConstraint> {
    override fun create(): SealedSenderConstraint = SealedSenderConstraint
  }
}
