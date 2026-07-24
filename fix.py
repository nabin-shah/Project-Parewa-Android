import re

with open("app/src/main/java/org/thoughtcrime/securesms/contacts/sync/ContactDiscoveryRefreshV2.kt", "r") as f:
    content = f.read()

content = content.replace(
    'okhttp3.RequestBody.create(okhttp3.MediaType.parse("application/json"), jsonBody.toString())',
    'okhttp3.RequestBody.create(okhttp3.MediaType.parse("application/json"), jsonBody.toString())'.replace('okhttp3.MediaType.parse', 'okhttp3.MediaType.parse')
)

# Actually, let's just use regular expressions
content = re.sub(
    r'okhttp3\.RequestBody\.create\(okhttp3\.MediaType\.parse\("application/json"\),\s*jsonBody\.toString\(\)\)',
    r'okhttp3.RequestBody.create(null, jsonBody.toString())', # No, backend needs content-type.
    content
)

with open("app/src/main/java/org/thoughtcrime/securesms/contacts/sync/ContactDiscoveryRefreshV2.kt", "w") as f:
    f.write(content)
