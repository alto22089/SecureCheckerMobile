package com.example.myapplication

import com.google.gson.annotations.SerializedName

// JSON全体を表すトップレベルのクラス
data class UrlScanResponseGson(
    @SerializedName("success")
    val success: Boolean,

    @SerializedName("urlscan")
    val urlscan: UrlScanInfoGson?,

    @SerializedName("virustotal")
    val virustotal: VirusTotalInfoGson?,

    @SerializedName("target")
    val target: String?
)

// "urlscan": { ... } の中身
data class UrlScanInfoGson(
    @SerializedName("custom_rating")
    val custom_rating: String,

    @SerializedName("security_state_summary")
    val security_state_summary: SecurityStateSummaryInfoGson?,

    @SerializedName("task")
    val task: TaskInfoGson?,

    @SerializedName("verdicts")
    val verdicts: VerdictsInfoGson?
)

// "security_state_summary": { ... } の中身
data class SecurityStateSummaryInfoGson(
    @SerializedName("secure")
    val secure: Int,

    @SerializedName("insecure")
    val insecure: Int,

    @SerializedName("unknown")
    val unknown: Int,

    @SerializedName("total")
    val total: Int,
)

// "task": { ... } の中身
data class TaskInfoGson(
    @SerializedName("url")
    val url: String?,

    @SerializedName("screenshotURL")
    val screenshotURL: String?,

    @SerializedName("time")
    val time: String
)

// "verdicts": { ... } の中身
data class VerdictsInfoGson(
    @SerializedName("community")
    val community: CommunityInfoGson?,

    @SerializedName("engines")
    val engines: EnginesInfoGson?,

    @SerializedName("overall")
    val overall: OverallInfoGson?,

    @SerializedName("urlscanData")
    val urlscanData: UrlscanDataInfoGson?
)

// "community": { ... } の中身
data class CommunityInfoGson(
    @SerializedName("categories")
    val communityCategories: List<String>,

    @SerializedName("malicious")
    val communityMalicious: Boolean,

    @SerializedName("score")
    val communityScore: Int
)

// "engines": { ... } の中身
data class EnginesInfoGson(
    @SerializedName("categories")
    val enginesCategories: List<String>,

    @SerializedName("malicious")
    val enginesMalicious: Boolean,

    @SerializedName("score")
    val enginesScore: Int
)

// "overall": { ... } の中身
data class OverallInfoGson(
    @SerializedName("categories")
    val overallCategories: List<String>,

    @SerializedName("malicious")
    val overallMalicious: Boolean,

    @SerializedName("score")
    val overallScore: Int
)

// "urlscan": { ... } の中身
data class UrlscanDataInfoGson(
    @SerializedName("categories")
    val urlscanCategories: List<String>,

    @SerializedName("malicious")
    val urlscanMalicious: Boolean,

    @SerializedName("score")
    val urlscanScore: Int
)

// "virustotal": { ... } の中身
data class VirusTotalInfoGson(
    @SerializedName("data")
    val data: VirusTotalDataGson?
)

// "data": { ... } の中身
data class VirusTotalDataGson(
    @SerializedName("attributes")
    val attributes: VirusTotalAttributesGson?,

    @SerializedName("summary")
    val summary: VirusTotalSummaryGson?,

    @SerializedName("category")
    val category: VirusTotalCategoryGson?,

    @SerializedName("type")
    val type: String
)

// "attributes": { ... } の中身
data class VirusTotalAttributesGson(
    // JSONのキーが日本語なので、@SerializedNameが必須
    @SerializedName("安全")
    val safe: Int,

    @SerializedName("悪意あり")
    val malicious: Int,

    @SerializedName("疑わしい")
    val suspicious: Int,

    @SerializedName("最終分析日時")
    val lastAnalysisDate: String
)

// "summary": { ... } の中身
data class VirusTotalSummaryGson(
    @SerializedName("rating")
    val rating: String,

    @SerializedName("positives")
    val positives: Int,

    @SerializedName("total")
    val total: Int
)

data class VirusTotalCategoryGson(
    @SerializedName("actions")
    val action: List<String>,

    @SerializedName("description")
    val descripton: String,

    @SerializedName("name")
    val categoryName: String,

    @SerializedName("recommendation")
    val recommendation: String,

    @SerializedName("risk_level")
    val risk_level: String
)