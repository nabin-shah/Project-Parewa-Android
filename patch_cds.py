import re

with open("app/src/main/java/org/thoughtcrime/securesms/contacts/sync/ContactDiscoveryRefreshV2.kt", "r") as f:
    content = f.read()

replacement = """    val transformed: MutableMap<String, CdsV2Result> = mutableMapOf()
    
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
        val responseBody = response.body()?.string()
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
              transformed[key] = CdsV2Result(org.signal.core.models.ServiceId.PNI(org.signal.core.util.UuidUtil.parseOrNull(pni) ?: java.util.UUID.randomUUID()), org.signal.core.models.ServiceId.ACI(org.signal.core.util.UuidUtil.parseOrNull(uuid) ?: java.util.UUID.randomUUID()))
            }
          }
        }
      }
    } catch (e: Exception) {
      Log.e(TAG, "Parewa directory sync failed", e)
      throw IOException(e)
    }
"""

start_str = "    val result = SignalNetwork.cdsApi.getRegisteredUsers("
end_str = "    val transformed: Map<String, CdsV2Result> = response.results.mapValues { entry -> CdsV2Result(entry.value.pni, entry.value.aci.orElse(null)) }"

start_idx = content.find(start_str)
end_idx = content.find(end_str) + len(end_str)

if start_idx != -1 and end_idx != -1:
    new_content = content[:start_idx] + replacement + content[end_idx:]
    with open("app/src/main/java/org/thoughtcrime/securesms/contacts/sync/ContactDiscoveryRefreshV2.kt", "w") as f:
        f.write(new_content)
    print("Patched CDS.")
else:
    print("Could not find bounds.")
