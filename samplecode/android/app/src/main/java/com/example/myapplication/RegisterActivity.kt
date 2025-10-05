package com.example.myapplication

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.Toast
import org.json.JSONObject
import retrofit2.Call
import retrofit2.Callback
import retrofit2.Response

class RegisterActivity : Activity() {

    private lateinit var api: ApiService

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_register)

        api = ApiClient.retrofit.create(ApiService::class.java)
        val session = SessionManager(this)

        val btnRegisterSubmit = findViewById<Button>(R.id.btnRegisterSubmit)
        val cbAgree = findViewById<CheckBox>(R.id.cbAgree)

        cbAgree.setOnCheckedChangeListener { _, isChecked ->
            btnRegisterSubmit.isEnabled = isChecked
        }

        btnRegisterSubmit.setOnClickListener {
            val username = findViewById<EditText>(R.id.editUsername).text.toString()
            val password = findViewById<EditText>(R.id.editPassword).text.toString()

            if (username.isBlank() || password.isBlank()) {
                Toast.makeText(this, "ユーザー名とパスワードを入力してください", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            // 半角英数字と記号のみチェック
            val regex = Regex("^[a-zA-Z0-9!@#\$%^&*()_+=\\-\\[\\]{};:'\",.<>/?]+$")
            if (!regex.matches(username)) {
                Toast.makeText(this, "ユーザー名は半角英数字と記号のみです", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            if (!regex.matches(password)) {
                Toast.makeText(this, "パスワードは半角英数字と記号のみです", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            val body = mapOf("username" to username, "password" to password)
            api.register(body).enqueue(object : Callback<ApiService.RegisterResponse> {
                override fun onResponse(
                    call: Call<ApiService.RegisterResponse>,
                    response: Response<ApiService.RegisterResponse>
                ) {
                    if (response.code() == 201){
                        val msg = response.body()?.message ?: "登録成功"
                        Toast.makeText(this@RegisterActivity, msg, Toast.LENGTH_LONG).show()
                        finish()
                    } else {
                        val errorBody = response.errorBody()?.string()
                        val msg = try {
                            val json = JSONObject(errorBody ?: "")
                            json.optString("error", "不明なエラー")  // "error"キーを優先
                        } catch (e: Exception) {
                            errorBody ?: "不明なエラー"  // JSONでなければそのまま文字列を表示
                        }

                        Toast.makeText(this@RegisterActivity, msg, Toast.LENGTH_LONG).show()

                    }
                }

                override fun onFailure(call: Call<ApiService.RegisterResponse>, t: Throwable) {
                    Toast.makeText(this@RegisterActivity, "通信エラー: ${t.message}", Toast.LENGTH_SHORT).show()
                }
            })
        }

        findViewById<Button>(R.id.btnBack).setOnClickListener { finish() }
    }
}
