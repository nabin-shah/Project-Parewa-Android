package org.thoughtcrime.securesms.registration.ui.email

import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.activityViewModels
import androidx.navigation.fragment.findNavController
import com.google.android.material.textfield.TextInputEditText
import org.signal.core.ui.logging.LoggingFragment
import org.signal.core.util.logging.Log
import org.thoughtcrime.securesms.R
import org.thoughtcrime.securesms.components.ViewBinderDelegate
import org.thoughtcrime.securesms.databinding.FragmentRegistrationEmailEntryBinding
import org.thoughtcrime.securesms.registration.data.ParewaRegistrationApi
import org.thoughtcrime.securesms.registration.ui.RegistrationViewModel
import org.thoughtcrime.securesms.util.ViewUtil
import org.thoughtcrime.securesms.util.navigation.safeNavigate

class EmailEntryFragment : LoggingFragment(R.layout.fragment_registration_email_entry) {

  private val sharedViewModel: RegistrationViewModel by activityViewModels()
  private val binding by ViewBinderDelegate(FragmentRegistrationEmailEntryBinding::bind)

  private lateinit var emailInput: TextInputEditText

  companion object {
    private val TAG = Log.tag(EmailEntryFragment::class.java)
  }

  override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
    super.onViewCreated(view, savedInstanceState)

    requireActivity().onBackPressedDispatcher.addCallback(
      viewLifecycleOwner,
      object : OnBackPressedCallback(true) {
        override fun handleOnBackPressed() {
          findNavController().popBackStack()
        }
      }
    )

    emailInput = binding.emailInputLayout.editText as TextInputEditText

    binding.nextButton.setOnClickListener {
      startEmailRegistration()
    }

    sharedViewModel.uiState.observe(viewLifecycleOwner) { sharedState ->
      updateEnabledControls(sharedState.inProgress)

      if (sharedState.parewaOtpRequested) {
        Log.d(TAG, "Parewa OTP requested, moving to verification screen.")
        sharedViewModel.setInProgress(false)
        findNavController().safeNavigate(EmailEntryFragmentDirections.actionEnterCode())
      }

      sharedState.parewaOtpError?.let { error ->
        Log.w(TAG, "Parewa OTP error: $error")
        Toast.makeText(requireContext(), error, Toast.LENGTH_LONG).show()
        sharedViewModel.setInProgress(false)
      }
    }

    val existingEmail = sharedViewModel.state.value.email
    if (existingEmail != null) {
      emailInput.setText(existingEmail)
    }

    ViewUtil.focusAndShowKeyboard(emailInput)
  }

  private fun startEmailRegistration() {
    ViewUtil.hideKeyboard(requireContext(), emailInput)
    sharedViewModel.setInProgress(true)

    val emailText = emailInput.text?.toString()?.trim() ?: ""

    if (emailText.isEmpty() || !ParewaRegistrationApi.isValidEmail(emailText)) {
      Log.w(TAG, "Invalid email format: $emailText")
      Toast.makeText(requireContext(), "Please enter a valid email address", Toast.LENGTH_SHORT).show()
      sharedViewModel.setInProgress(false)
      return
    }

    Log.d(TAG, "Starting Parewa email registration for: $emailText")
    
    // Set the email in the ViewModel so the code fragment can use it
    sharedViewModel.setEmail(emailText)

    // Generate a fake E164 from the email for internal Signal compatibility if a phone wasn't collected
    val fakeE164 = ParewaRegistrationApi.emailToFakeE164(emailText)
    Log.d(TAG, "Generated fake E164 for internal compat: $fakeE164")

    // Request OTP from our local backend
    sharedViewModel.requestParewaOtp(emailText)
  }

  private fun updateEnabledControls(showProgress: Boolean) {
    binding.emailInputLayout.isEnabled = !showProgress
    binding.nextButton.isEnabled = !showProgress
  }
}
