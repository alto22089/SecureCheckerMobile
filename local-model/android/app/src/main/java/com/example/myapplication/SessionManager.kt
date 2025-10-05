package com.example.myapplication

import android.content.Context

class SessionManager(private val context: Context) {

    private val prefs = context.getSharedPreferences("secure_checker_prefs", Context.MODE_PRIVATE)

    fun saveToken(token: String) {
        prefs.edit().putString("jwt_token", token).apply()
    }

    fun getToken(): String? {
        return prefs.getString("jwt_token", null)
    }

    fun clearToken() {
        prefs.edit().remove("jwt_token").apply()
    }
}
