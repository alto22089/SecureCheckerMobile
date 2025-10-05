package com.example.myapplication

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import org.json.JSONObject
import retrofit2.Call
import retrofit2.Callback
import retrofit2.Response

class LoginActivity : Activity() {

    private lateinit var api: ApiService
    private lateinit var session: SessionManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)

        api = ApiClient.retrofit.create(ApiService::class.java)
        session = SessionManager(this)

        val btnLogin = findViewById<Button>(R.id.btnLoginSubmit)
        val editUsername = findViewById<EditText>(R.id.editUsername)
        val editPassword = findViewById<EditText>(R.id.editPassword)
        val btnGoRegister = findViewById<Button>(R.id.btnGoRegister)

        btnLogin.setOnClickListener {
            val username = editUsername.text.toString()
            val password = editPassword.text.toString()

            if (username.isBlank() || password.isBlank()) {
                Toast.makeText(this, "ユーザー名とパスワードを入力してください", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            val body = mapOf("username" to username, "password" to password)
            api.login(body).enqueue(object : Callback<ApiService.LoginResponse> {
                override fun onResponse(
                    call: Call<ApiService.LoginResponse>,
                    response: Response<ApiService.LoginResponse>
                ) {
                    if (response.code() == 200) {
                        val token = response.body()?.token
                        if (!token.isNullOrBlank()) {
                            session.saveToken(token)
                            Toast.makeText(this@LoginActivity, "ログインに成功しました", Toast.LENGTH_SHORT).show()
                            startActivity(Intent(this@LoginActivity, MainActivity::class.java))
                            finish()
                        } else {
                            Toast.makeText(this@LoginActivity, "ログイン失敗: トークンが取得できません", Toast.LENGTH_LONG).show()
                        }
                    } else {
                        val errorBody = response.errorBody()?.string()
                        val msg = try {
                            val json = JSONObject(errorBody ?: "")
                            json.optString("message", "不明なエラー")
                        } catch (e: Exception) {
                            errorBody ?: "不明なエラー"  // JSONでなければそのまま文字列を表示
                        }
                        Toast.makeText(this@LoginActivity, msg, Toast.LENGTH_LONG).show()
                    }
                }

                override fun onFailure(call: Call<ApiService.LoginResponse>, t: Throwable) {
                    Toast.makeText(this@LoginActivity, "通信エラー: ${t.message}", Toast.LENGTH_SHORT).show()
                }
            })
        }

        btnGoRegister.setOnClickListener {
            startActivity(Intent(this, RegisterActivity::class.java))
        }
    }
}
