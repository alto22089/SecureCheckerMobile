package com.example.myapplication

import android.content.Context
import android.util.Log
import java.io.FileNotFoundException
import java.net.MalformedURLException
import java.net.URL

object AdBlocker {
    private val adHosts = mutableSetOf<String>()

    fun init(context: Context) {
        try {
            val inputStream = context.assets.open("output.txt")
            inputStream.bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    if (line.isNotBlank()) adHosts.add(line.trim())
                }
            }
        } catch (e: FileNotFoundException) {
            Log.e("AdBlocker", "hosts.txt not found", e)
            // デフォルトの広告ホストを使う、または空のままにする
        } catch (e: Exception) {
            Log.e("AdBlocker", "Error loading hosts.txt", e)
        }
    }

    fun isAd(url: String): Boolean {
        val host = try {
            URL(url).host
        } catch (e: MalformedURLException) {
            null
        }
        return host != null && adHosts.any { host.contains(it) }
    }
}
