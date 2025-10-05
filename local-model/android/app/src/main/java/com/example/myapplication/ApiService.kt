package com.example.myapplication

import android.net.Uri
import okhttp3.MultipartBody
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.Header
import retrofit2.http.Multipart
import retrofit2.http.POST
import retrofit2.http.Part
import retrofit2.Call
import okhttp3.ResponseBody



// --- データクラス (JSONの構造に合わせる) ---
data class UrlScanRequest(val url: String)
data class IpScanRequest(val ip: String)
data class HashScanRequest(val hash: String)
data class FileScanRequest(val file: Uri)

// 汎用的なレスポンスの例。実際のレスポンスに合わせて変更してください。
data class ScanResponse(val status: String, val message: String, val data: Map<String, Any>?)


// --- APIのインターフェース ---
interface ApiService {
    @POST("scan/url")
    suspend fun scanUrl(
        @Header("x-access-token") token: String,
        @Body request: UrlScanRequest
    ): Response<UrlScanResponseGson> // レスポンスの型は実際のJSONに合わせて調整

    @POST("scan/ip")
    suspend fun scanIp(
        @Header("x-access-token") token: String,
        @Body request: IpScanRequest
    ): Response<ScanResponse>

    @POST("scan/file/check")
    suspend fun scanHash(
        @Header("x-access-token") token: String,
        @Body request: HashScanRequest
    ): Response<FileScanResponse>

    @Multipart
    @POST("scan/file/upload")
    suspend fun scanFile(
        @Header("x-access-token") token: String,
        @Part file: MultipartBody.Part // ファイルを送信
    ): Response<FileScanResponse>


    data class RegisterResponse(
        val success: Boolean? = null,
        val message: String? = null,
        val error: String? = null
    )

    data class LoginResponse(
        val token: String? = null,
        val message: String? = null
    )

    @POST("register")
    fun register(@Body body: Map<String, String>): Call<RegisterResponse>

    @POST("login")
    fun login(@Body body: Map<String, String>): Call<LoginResponse>
}