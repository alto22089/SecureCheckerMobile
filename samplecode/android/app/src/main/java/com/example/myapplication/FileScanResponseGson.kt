package com.example.myapplication

import com.google.gson.annotations.SerializedName

data class FileScanResponse(
    @SerializedName("data")
    val data: ApiData?, // エラーの場合nullになる可能性があるため nullable に


    @SerializedName("success")
    val success: Boolean
)

// "data" オブジェクトに対応
data class ApiData(
    @SerializedName("attributes")
    val attributes: Attributes,

    @SerializedName("category")
    val category: Category,

    @SerializedName("details")
    val details: List<Detail>,

    @SerializedName("summary")
    val summary: Summary,

    @SerializedName("target")
    val target: String,

    @SerializedName("type")
    val type: String
)

// "attributes" オブジェクトに対応
// 日本語キーを @SerializedName でマッピング
data class Attributes(
    @SerializedName("安全")
    val safe: Int,

    @SerializedName("悪意あり")
    val malicious: Int,

    @SerializedName("最終分析日時")
    val lastAnalysisDate: String,

    @SerializedName("未検出")
    val undetected: Int,

    @SerializedName("疑わしい")
    val suspicious: Int
)

// "category" オブジェクトに対応
data class Category(
    @SerializedName("actions")
    val action: List<String>,

    @SerializedName("description")
    val description: String,

    @SerializedName("name")
    val categoryName: String,

    @SerializedName("recommendation")
    val recommendation: String,

    @SerializedName("risk_level")
    val risk_level: String // snake_case を camelCase にマッピング
)

// "details" 配列の各要素に対応
data class Detail(
    @SerializedName("category")
    val category: String,

    @SerializedName("result")
    val result: String?, // JSONでnullなので nullable に

    @SerializedName("vendor")
    val vendor: String
)

// "summary" オブジェクトに対応
data class Summary(
    @SerializedName("positives")
    val positives: Int,

    @SerializedName("rating")
    val rating: String,

    @SerializedName("total")
    val total: Int
)