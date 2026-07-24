import re

with open("app/src/main/java/org/thoughtcrime/securesms/contacts/sync/ContactDiscoveryRefreshV2.kt", "r") as f:
    content = f.read()

content = content.replace(
    'okhttp3.RequestBody.create(null, jsonBody.toString())',
    'okhttp3.RequestBody.create(okhttp3.MediaType.parse("application/json"), jsonBody.toString())' # Revert first
)

# Replace with extension function syntax if possible, or fully qualified Companion method
content = content.replace(
    'okhttp3.RequestBody.create(okhttp3.MediaType.parse("application/json"), jsonBody.toString())',
    'okhttp3.RequestBody.create(okhttp3.MediaType.parse("application/json"), jsonBody.toString())' # wait okhttp3.RequestBody.create(...) is also deprecated
)

content = content.replace(
    'okhttp3.RequestBody.create(okhttp3.MediaType.parse("application/json"), jsonBody.toString())',
    'okhttp3.RequestBody.Companion.create(jsonBody.toString(), okhttp3.MediaType.Companion.parse("application/json"))'
)

with open("app/src/main/java/org/thoughtcrime/securesms/contacts/sync/ContactDiscoveryRefreshV2.kt", "w") as f:
    f.write(content)
