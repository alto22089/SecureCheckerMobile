package com.example.myapplication

import android.app.Application
import android.content.Context
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.google.gson.GsonBuilder
import kotlinx.coroutines.launch
import android.net.Uri
import android.util.Log
import android.util.Patterns
import androidx.lifecycle.AndroidViewModel
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.asRequestBody
import okhttp3.Response
import org.json.JSONObject
import java.io.File
import java.io.IOException

// UIの状態を表すデータクラス
data class UiState(
    val isLoading: Boolean = false,
    val urlResponse: UrlScanResponseGson? = null,
    var error: String? = null,
    val nowUrl: String? = null,
    val fileResponse: FileScanResponse? = null
)



class SecureCheckerViewModel(application: Application, initialUrl: String?) : AndroidViewModel(application) {

    var uiState = mutableStateOf(UiState())
        private set
    // --- TextFieldの入力値を保持する状態 ---
    var urlText = mutableStateOf(initialUrl ?: "") // 受け取ったURLで初期化
        private set
    var ipText = mutableStateOf("")
        private set
    var hashText = mutableStateOf("")
        private set

    var approvedUrlToLoad = mutableStateOf<String?>(null)
        private set

    var pendingUnsafeUrl = mutableStateOf<String?>(null)

    var showUrlValidationErrorDialog = mutableStateOf(false)
        private set

    var showUploadPrompt = mutableStateOf(false)
        private set

    fun onUrlLoaded() {
        approvedUrlToLoad.value = null
        pendingUnsafeUrl.value = null
    }

    // ダイアログを閉じるための関数
    fun dismissUrlValidationErrorDialog() {
        showUrlValidationErrorDialog.value = false
    }

    // --- TextFieldの値が変更されたときに呼び出す関数 ---
    fun onUrlTextChanged(newText: String) {
        urlText.value = newText
    }
    fun onIpTextChanged(newText: String) {
        ipText.value = newText
    }
    fun onHashTextChanged(newText: String) {
        hashText.value = newText
    }

    private val sessionManager = SessionManager(application)
    private val token = sessionManager.getToken() ?: ""
    private val apiService = RetrofitClient.apiService

    // きれいにフォーマットされたJSONを生成するためのGsonインスタンス
    private val gson = GsonBuilder().setPrettyPrinting().create()
    fun test(url: String) {
        val urlToScan = url.ifBlank { urlText.value }
        uiState.value = UiState(isLoading = true, urlResponse = null, error = null)
        println("ssss")
        if (true) {
            approvedUrlToLoad.value = urlToScan
        }
        else {
            showUrlValidationErrorDialog.value = true
        }


    }

    fun reset() {
        uiState.value = UiState(
            isLoading = false,
            urlResponse = null,
            fileResponse = null,
            error = null,
            nowUrl = null
        )
    }

    fun resetAllStates() {
        uiState.value = UiState(
            isLoading = false,
            urlResponse = null,
            fileResponse = null,
            error = null,  // ← safe/unsafe 状態を完全クリア
            nowUrl = null
        )
        approvedUrlToLoad.value = null
        pendingUnsafeUrl.value = null
        showUrlValidationErrorDialog.value = false
        showUploadPrompt.value = false  // ← 念のため追加
        urlText.value = ""  // ← 入力欄もリセットしたい場合
        ipText.value = ""
        hashText.value = ""
    }


    fun scanUrl(url: String) {
        val urlToScan = url.ifBlank { urlText.value }
        uiState.value = UiState(isLoading = false, urlResponse = null, error = null)
        // 1. 空白でないかチェック
        if (urlToScan.isBlank()) {
            return
        }

        // 2. URLの形式が正しいかチェック
        if (!Patterns.WEB_URL.matcher(urlToScan).matches()) {
            // もしURLの形式でなければ、エラーメッセージを設定して処理を中断
            //uiState.value = UiState(error = "正しい形式のURLを入力してください。")
            showUrlValidationErrorDialog.value = true
            return
        }


        // UIの状態を「ローディング中」に更新
        uiState.value = UiState(isLoading = true, urlResponse = null, error = null)
        println("ssss")
        viewModelScope.launch {
            try {
                // ViewModelが保持しているurlText.valueを使う
                println("aaaa")
                val request = UrlScanRequest(url =  urlToScan)
                val response = apiService.scanUrl(token = token, request = request)
                if (response.isSuccessful) {
                    println("bbbb")
                    val scanResponse = response.body()
                    if (scanResponse?.success == true) {
                        uiState.value = UiState(isLoading = false, urlResponse = response.body())
                        Log.d("log","$[UISTATE]")
                        Log.d("log","${uiState.value}")
                        val rating = scanResponse?.virustotal?.data?.summary?.rating
                        println("rating:::" + rating)
                        if (rating != null && rating.contains("\uD83D\uDFE2")) {
                            // 安全と判断されたら、読み込むべきURLをセットする
                            uiState.value.error = "safe"
                            Log.d("log","$[UISTATE]")
                            Log.d("log","${uiState.value}")
                            println("aaaaaaaaaa")
                            pendingUnsafeUrl.value = urlToScan
                        } else {
                            // 安全でない、または不明な場合は何もしない（ダイアログ表示はUI側に任せる）
                            uiState.value.error = "unsafe"
                            pendingUnsafeUrl.value = urlToScan
                            println("dsdsds")
                        }
                    }
                    else {
                        val serverErrorMessage = "サーバーが混み合っているか、一時的な問題が発生しました。時間を置いて再度お試しください。"
                        uiState.value = UiState(isLoading = false, error = serverErrorMessage)
                    }
                } else {
                    val errorBody = response.errorBody()?.string() // ここで文字列を読む
                    Log.d("ServerError", "Raw errorBody: $errorBody")

                    val errorMessage = try {
                        val json = JSONObject(errorBody ?: "{}")
                        json.optString("message", "サーバーからのエラーメッセージがありません")
                    } catch (e: Exception) {
                        Log.e("ServerError", "JSONパース失敗: ${e.message}")
                        "エラー解析に失敗しました"
                    }
                    uiState.value = UiState(isLoading = false, error = errorMessage)

                }
            } catch (e: Exception) {
                uiState.value = UiState(isLoading = false, error = "サーバーにアクセスできませんでした" ?: "Exception occurred")

            }

        }
    }
    fun scanIp(ip: String) {

    }

    fun scanHash(hash: String) {

    }

    fun scanFile (hash: String) {
        uiState.value = UiState(isLoading = true, fileResponse = null, error = null)

        viewModelScope.launch {
            try {
                // ViewModelが保持しているurlText.valueを使う
                val request = HashScanRequest(hash = hash)
                val response = apiService.scanHash(token = token, request = request)
                if (response.isSuccessful) {

                    val scanResponse = response.body()
                    if (scanResponse?.success == true) {
                        uiState.value = UiState(isLoading = false, fileResponse = response.body())
                        val rating = scanResponse?.data?.summary?.rating
                        println("rating:::" + rating)
                        if (rating != null && rating.contains("安全")) {
                            // 安全と判断されたら、読み込むべきURLをセットする
                            println("安全")

                        }
                        else if (rating != null && rating.contains("注意")){
                            // 安全でない、または不明な場合は何もしない（ダイアログ表示はUI側に任せる）
                            println("注意")
                        }
                        else if (rating != null && rating.contains("疑")){
                            // 安全でない、または不明な場合は何もしない（ダイアログ表示はUI側に任せる）
                            println("疑わしい")
                        }
                        else if (rating != null && rating.contains("危")){
                            // 安全でない、または不明な場合は何もしない（ダイアログ表示はUI側に任せる）
                            println("危険")
                        }
                        else if (rating != null && rating.contains("情報")){
                            // 安全でない、または不明な場合は何もしない（ダイアログ表示はUI側に任せる）
                            println("情報不足")
                            showUploadPrompt.value = true
                        } else {
                            println("判定不可")
                        }

                    }
                    else {
                        val serverErrorMessage = "サーバーが混み合っているか、一時的な問題が発生しました。時間を置いて再度お試しください。"
                        uiState.value = UiState(isLoading = false, error = serverErrorMessage)
                    }
                } else {
                    val errorBody = response.errorBody()?.string() // ここで文字列を読む
                    Log.d("ServerError", "Raw errorBody: $errorBody")

                    val errorMessage = try {
                        val json = JSONObject(errorBody ?: "{}")
                        json.optString("message", "サーバーからのエラーメッセージがありません")
                    } catch (e: Exception) {
                        Log.e("ServerError", "JSONパース失敗: ${e.message}")
                        "エラー解析に失敗しました"
                    }
                    uiState.value = UiState(isLoading = false, error = errorMessage)
                }
            } catch (e: Exception) {
                uiState.value = UiState(isLoading = false, error = e.message ?: "Exception occurred")
            }

        }
    }



    fun uploadFile(context: Context, uri: Uri) {
        uiState.value = UiState(isLoading = true, fileResponse = null, error = null)
        viewModelScope.launch {
            try {
                val inputStream = context.contentResolver.openInputStream(uri)
                val fileBytes = inputStream?.readBytes()
                inputStream?.close()

                if (fileBytes != null) {
                    // 一時ファイル作成
                    val tempFile = File(context.cacheDir, "upload.tmp")
                    tempFile.writeBytes(fileBytes)

                    val requestBody = tempFile.asRequestBody("application/octet-stream".toMediaTypeOrNull())
                    val multipart = MultipartBody.Part.createFormData("file", tempFile.name, requestBody)

                    // Retrofit 呼び出し
                    val response = apiService.scanFile(token, multipart)

                    if (response.isSuccessful) {
                        val scanResponse = response.body()
                        if (scanResponse?.success == true) {
                            uiState.value = UiState(isLoading = false, fileResponse = response.body())
                            val rating = scanResponse?.data?.summary?.rating
                            println("rating:::" + rating)

                            showUploadPrompt.value = false
                            if (rating != null && rating.contains("安全")) {
                                // 安全と判断されたら、読み込むべきURLをセットする
                                println("安全")

                            }
                            else if (rating != null && rating.contains("注意")){
                                // 安全でない、または不明な場合は何もしない（ダイアログ表示はUI側に任せる）
                                println("注意")
                            }
                            else if (rating != null && rating.contains("疑")){
                                // 安全でない、または不明な場合は何もしない（ダイアログ表示はUI側に任せる）
                                println("疑わしい")
                            }
                            else if (rating != null && rating.contains("危")){
                                // 安全でない、または不明な場合は何もしない（ダイアログ表示はUI側に任せる）
                                println("危険")
                            }
                            else if (rating != null && rating.contains("情報")){
                                // 安全でない、または不明な場合は何もしない（ダイアログ表示はUI側に任せる）
                                println("情報不足")
                                //showUploadPrompt.value = true
                            } else {
                                println("判定不可")
                            }

                        }




                    } else {
                        uiState.value = uiState.value.copy(
                            error = "VirusTotal送信に失敗しました (HTTP ${response.code()})",
                            isLoading = false
                        )
                    }
                } else {
                    uiState.value = uiState.value.copy(error = "ファイルを読み取れませんでした", isLoading = false)
                }
            } catch (e: Exception) {
                uiState.value = uiState.value.copy(error = "送信エラー: ${e.message}", isLoading = false)
            }
        }
    }

    fun postFeedback(feedbackText: String, onResult: (success: Boolean, message: String) -> Unit) {
        val client = OkHttpClient()

        // サーバー仕様に合わせて "content" キーで送信
        val json = JSONObject().apply {
            put("content", feedbackText)
        }

        val requestBody = RequestBody.create(
            "application/json; charset=utf-8".toMediaTypeOrNull(),
            json.toString()
        )

        val url = BASE_URL + "feedback"

        val request = Request.Builder()
            .url(url)
            .post(requestBody) // POST送信
            .addHeader("x-access-token", token) // token_requiredを通す場合、ヘッダにトークンを追加
            .build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                onResult(false, e.message ?: "送信失敗")
            }

            override fun onResponse(call: Call, response: Response) {
                if (response.isSuccessful) {
                    onResult(true, "送信成功")
                } else {
                    val errorMsg = response.body?.string() ?: "サーバーエラー: ${response.code}"
                    onResult(false, errorMsg)
                }
            }
        })
    }
}