package com.example.myapplication

import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import com.example.myapplication.ui.theme.AppTheme
import androidx.compose.ui.Alignment
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.unit.dp
import android.content.Intent
import androidx.compose.ui.window.Dialog
import android.widget.TextView
import android.util.Log
import android.webkit.WebResourceRequest
import androidx.activity.viewModels
import androidx.compose.foundation.rememberScrollState
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import android.webkit.WebResourceResponse
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.RequiresApi
import androidx.compose.foundation.clickable
import androidx.compose.ui.layout.ContentScale
import coil.compose.AsyncImage
import okhttp3.*                   // OkHttpClient, Request, RequestBody, Callback, Response
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.RequestBody
import java.io.IOException          // ネットワーク例外用
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.background

import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.net.URL
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.runtime.remember
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow

import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.net.HttpURLConnection
import java.net.URLEncoder
import java.security.MessageDigest


class MainActivity : ComponentActivity() {
    @RequiresApi(Build.VERSION_CODES.O)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 共有インテントからURLを取得
        val sharedUrl = getSharedUrl(intent)
        val realUrl = extractActualUrl(sharedUrl)

        // Factoryを使ってViewModelを生成し、初期URLを渡す
        val viewModel: SecureCheckerViewModel by viewModels {
            SecureCheckerViewModelFactory(application,realUrl)
        }

        enableEdgeToEdge()

        // 共有URLがあるかどうかで、最初の画面（ルート）を決定する
        val startRoute = if (sharedUrl != null) {
            "secure_checker_screen" // 共有URLがあれば、チェッカー画面から開始
        } else {
            "start_screen" // なければ、スタート画面から開始
        }

        enableEdgeToEdge()

        setContent {
            AppTheme {
                // 画面遷移を管理するNavControllerを初期化
                val navController = rememberNavController()
                var query by remember { mutableStateOf("") }
                // NavHostの開始地点を先ほど決めた変数に変更
                NavHost(navController = navController, startDestination = startRoute) {

                    // 1. スタート画面 ("/start_screen") の定義
                    composable("start_screen") {
                        StartScreen(
                            onStartClick = {
                                // ボタンが押されたらメイン画面へ遷移
                                navController.navigate("secure_checker_screen")
                            },
                            onStartBrowserClick = {
                                navController.navigate("browser_search")
                            },
                            onFeedbackClick = {
                                // 新しいフィードバック画面へ遷移
                                navController.navigate("feedback_screen")
                            }

                        )
                    }
                    composable("secure_checker_screen") {
                        SecureCheckerScreen(
                            viewModel = viewModel,
                            onNavigateBack = {
                                navController.navigate("start_screen") {
                                    popUpTo(navController.graph.startDestinationId) {
                                        inclusive = true
                                    }
                                }
                            }
                        )
                    }


                    composable("browser_search") {

                        val context = LocalContext.current

                        SearchBoxScreen(
                            query = query,
                            onQueryChange = { query = it },
                            onSearch = {
                                // WebView画面へ遷移
                                if (query.isNotEmpty()) {
                                    viewModel.reset()
                                    val url = "https://www.google.com/search?q=" +
                                            URLEncoder.encode(query, "UTF-8")
                                    navController.navigate("browser_webview/${Uri.encode(url)}")
                                    println("url:"+url)
                                }
                                else {
                                    Toast.makeText(
                                        context,
                                        "検索キーワードを入力してください",
                                        Toast.LENGTH_SHORT
                                    ).show()
                                }

                            },
                            onNavigateBack = {
                                query = ""
                                navController.popBackStack()
                            }
                        )
                    }

                    // 4. ブラウザWebView画面(修正)
                    composable(
                        "browser_webview/{url}",
                        arguments = listOf(navArgument("url") { type = NavType.StringType })
                    ) { backStackEntry ->
                        val url = backStackEntry.arguments?.getString("url") ?: ""
                        val destination = backStackEntry.destination
                        val context = LocalContext.current
                        var webViewRef by remember { mutableStateOf<WebView?>(null) }
                        var showWebView by remember { mutableStateOf(false) }

                        // 主な情報
                        println("shutoku:"+ url)
                        Log.d("Navigation", "Route: ${destination.route}")  // "browser_webview/{url}"
                        Log.d("Navigation", "ID: ${destination.id}")        // 一意のID
                        Log.d("Navigation", "Label: ${destination.label}")  // 画面のラベル

                        SimpleWebView(
                            url = url,
                            viewModel = viewModel,
                            onNavigateBack = {
                                viewModel.reset()
                                navController.popBackStack()
                            }

                        )
                        /*
                        SecureWebView(
                            viewModel = viewModel,
                            initialUrl = url,
                            onNavigateBack = {
                                navController.popBackStack()

                            }
                        )
                        */

                    }
                    // 5. フィードバック画面 ("/feedback_screen") の定義を新規追加
                    composable("feedback_screen") {
                        val context = LocalContext.current
                        FeedbackScreen(
                            onNavigateBack = {
                                // 前の画面（StartScreen）に戻る
                                navController.popBackStack()
                            },
                            onSendFeedback = { feedbackText ->
                                // 送信ボタンが押されたときの処理
                                Log.d("Feedback", "送信された内容: $feedbackText")

                                viewModel.postFeedback(feedbackText) { success, message ->
                                    runOnUiThread {
                                        // Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
                                    }
                                }

                                // ユーザーに完了を通知
                                Toast.makeText(
                                    context,
                                    "ご意見ありがとうございます！",
                                    Toast.LENGTH_SHORT
                                ).show()
                                navController.popBackStack()

                            }
                        )
                    }
                }
            }
        }
    }

    private fun getSharedUrl(from: Intent?): String? {
        return if (from?.action == Intent.ACTION_SEND && "text/plain" == intent.type) {
            from.getStringExtra(Intent.EXTRA_TEXT)
        } else {
            null
        }
    }

}







@Composable
fun HomeScreen() {
    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "ようこそ！",
            style = MaterialTheme.typography.headlineMedium
        )
        Text(
            text = "URLをチェックしたい場合は、ブラウザなどから共有してください。",
            modifier = Modifier.padding(top = 8.dp),
            textAlign = TextAlign.Center
        )
    }
}

@Composable
fun MainScreen(onNavigateBack: () -> Unit) {
    var query by remember { mutableStateOf("") }
    var searchUrl by remember { mutableStateOf("") }
    // 取得したURLを保持するための状態(state)を追加
    var clickedUrl by remember { mutableStateOf("") }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        // --- 検索バーと検索ボタンは変更なし ---
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(onClick = onNavigateBack) {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = "スタート画面に戻る"
                )
            }
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = "セキュアブラウザ",
                style = MaterialTheme.typography.headlineMedium
            )
        }
        Spacer(modifier = Modifier.height(8.dp))
        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            label = { Text("検索ワードを入力") },
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(modifier = Modifier.height(8.dp))
        Button(
            onClick = {
                if (query.isNotBlank()) {
                    searchUrl = "https://www.google.com/search?q=" +
                            URLEncoder.encode(query, "UTF-8")
                    // 新しい検索をしたら、前回クリックしたURLの表示をリセット
                    clickedUrl = ""
                }
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("検索")
        }
        Spacer(modifier = Modifier.height(16.dp))

        // --- ここから下が修正箇所 ---

        // 取得したURLを表示するText Composable
        if (clickedUrl.isNotEmpty()) {
            Text(
                text = "クリックされたURL:",
                style = MaterialTheme.typography.titleMedium
            )
            Text(
                text = clickedUrl,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.primary
            )
            Spacer(modifier = Modifier.height(16.dp))
        }


        if (searchUrl.isNotEmpty()) {
            AndroidView(
                factory = { context ->
                    WebView(context).apply {
                        settings.javaScriptEnabled = true
                        // ここでカスタムWebViewClientをセット
                        // コールバックで受け取ったURLを`clickedUrl` stateにセットする
                        webViewClient = MyWebViewClient { url ->
                            clickedUrl = url
                        }
                    }
                },
                update = { webView ->
                    if (webView.url != searchUrl) {
                        webView.loadUrl(searchUrl)
                    }
                },
                modifier = Modifier.fillMaxSize()
            )
        }
    }
}

@Preview(showBackground = true)
@Composable
fun PreviewMainScreen() {
    MainScreen({})
}

class MyWebViewClient(private val onUrlClick: (String) -> Unit) : WebViewClient() {

    // shouldOverrideUrlLoadingをオーバーライド
    override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
        // クリックされたURLを取得
        val clickedUrl = request?.url?.toString() ?: ""

        // URLが空でなければコールバックを呼び出してComposableに通知
        if (clickedUrl.isNotEmpty() && request?.hasGesture() == true) {
            println("touch")
            onUrlClick(clickedUrl)
            return false
        }




        // trueを返すことで、WebViewが自動でページ遷移するのを防ぐ
        return true
    }
}
//////////////////////

@RequiresApi(Build.VERSION_CODES.O)
@Composable
fun SecureCheckerScreen(viewModel: SecureCheckerViewModel, onNavigateBack: () -> Unit) {
    // ViewModelからUIの状態を取得
    val uiState by viewModel.uiState

    val context = LocalContext.current

    var selectedFileUri by remember { mutableStateOf<Uri?>(null) }
    var selectedFileName by remember { mutableStateOf<String?>(null) }

    // ファイル選択ランチャー
    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        uri?.let {
            selectedFileUri = it
            // ファイル名を取得して表示用に保持
            selectedFileName = queryFileName(context, it)
        }
    }



    if (viewModel.showUrlValidationErrorDialog.value) {
        AlertDialog(
            onDismissRequest = { viewModel.dismissUrlValidationErrorDialog() },
            containerColor = MaterialTheme.colorScheme.surfaceDim,
            title = {
                Text(
                    "入力エラー",
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.onSurface
                )
            },
            text = { Text("正しい形式のURLを入力してください。") },
            confirmButton = {
                TextButton(onClick = { viewModel.dismissUrlValidationErrorDialog() }) {
                    Text("OK")
                }
            }
        )
    }

    var selectedTabIndex by remember { mutableStateOf(0) }
    val tabs = listOf("URL", "ファイル")

    // 各タブの入力テキストの状態を管理
    var ipText by remember { mutableStateOf("") }
    var hashText by remember { mutableStateOf("") }



    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .padding(16.dp)
            .verticalScroll(rememberScrollState()) // 結果が長くてもスクロールできるようにする
    ) {
        // --- ▼▼▼ ここからが修正箇所 ▼▼▼ ---
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // 戻るボタン (引数で受け取った onNavigateBack を使用)
            IconButton(onClick = onNavigateBack) {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = "スタート画面に戻る"
                )
            }
            Spacer(modifier = Modifier.width(8.dp)) // ボタンとタイトルの間に少しスペースを追加
            // 画面タイトル
            Text(
                text = "セキュアチェッカーモバイル",
                fontSize = 20.sp,
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.primary,

            )
        }
        // --- ▲▲▲ ここまでが修正箇所 ▲▲▲ ---

        Spacer(modifier = Modifier.height(16.dp)) // レイアウト調整用のスペース

        TabRow(selectedTabIndex = selectedTabIndex) {
            tabs.forEachIndexed { index, title ->
                Tab(
                    selected = selectedTabIndex == index,
                    onClick = { selectedTabIndex = index },
                    text = { Text(text = title) }
                )
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        // 各タブの中身
        when (selectedTabIndex) {
            0 -> ScanUrlTab(
                value = viewModel.urlText.value,
                onValueChange = { viewModel.onUrlTextChanged(it) },
                onScanClick = { viewModel.scanUrl(viewModel.urlText.value) } // ViewModelの関数を呼び出す
            )
            1 -> ScanFileTab2(
                selectedFileName = selectedFileName,
                onFileSelectClick = {
                    filePickerLauncher.launch(arrayOf("*/*"))
                },
                onScanClick = {
                    selectedFileUri?.let { uri ->
                        val hash = calculateFileHash(context, uri)
                        println("HASH: $hash")
                        if (hash != null) {
                            viewModel.scanFile(hash)
                        }
                    }
                }
            )
            2 -> ScanIpTab(
                value = ipText,
                onValueChange = { ipText = it },
                onScanClick = { viewModel.scanIp(ipText) } // ViewModelの関数を呼び出す
            )
            3 -> ScanHashTab(
                value = hashText,
                onValueChange = { hashText = it },
                onScanClick = { viewModel.scanHash(hashText) } // ViewModelの関数を呼び出す
            )

        }

        Spacer(modifier = Modifier.height(24.dp))

        // --- 結果表示部分 ---
        ResultView(uiState = uiState, selectedTabIndex = selectedTabIndex, {
            selectedFileUri?.let { uri ->
                viewModel.uploadFile(context, uri)
            }
        })
    }
}


// --- 結果表示用のComposable ---
@RequiresApi(Build.VERSION_CODES.O)
@Composable
fun ResultView(uiState: UiState, selectedTabIndex: Int, onConfirmSend: () -> Unit) {

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .defaultMinSize(minHeight = 200.dp),
        contentAlignment = Alignment.TopStart // 上揃えに変更
    ) {
        when {
            uiState.isLoading -> {
                CircularProgressIndicator(modifier = Modifier.align(Alignment.Center))
            }
            uiState.error != null && uiState.error != "safe" && uiState.error != "unsafe"-> {
                Text(
                    text = "エラー:\n${uiState.error}",
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.align(Alignment.Center)
                )
            }

            selectedTabIndex == 0 && (uiState.urlResponse != null || uiState.error == "safe" || uiState.error == "unsafe") -> {
                UrlResultView(uiState)
            }
            selectedTabIndex == 1 && uiState.fileResponse != null -> {
                FileResultView(uiState, onConfirmSend)
            }
            else -> {
                Text("スキャン結果はまだありません。")
            }
        }
    }

}

@RequiresApi(Build.VERSION_CODES.O)
@Composable
fun UrlResultView(uiState: UiState) {
    var showDialog by remember { mutableStateOf(false)}


    val summary = uiState.urlResponse?.virustotal?.data?.summary
    val attributes = uiState.urlResponse?.virustotal?.data?.attributes
    val category = uiState.urlResponse?.virustotal?.data?.category
    Column {
        // --- VirusTotalの結果 ---
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                "検査したURL",
                style = MaterialTheme.typography.labelLarge,
                // 変更点: onTertiaryContainer に合わせる
                color = MaterialTheme.colorScheme.onTertiaryContainer
            )
            Surface(
                // 変更点: tertiaryContainer を使用
                color = MaterialTheme.colorScheme.tertiaryContainer,
                shape = MaterialTheme.shapes.small,
                modifier = Modifier.padding(top = 4.dp)
            ) {
                Text(
                    text = uiState.urlResponse?.target ?: "URLがありません",
                    style = MaterialTheme.typography.bodyLarge,
                    // 変更点: onTertiaryContainer を指定して文字色を最適化
                    color = MaterialTheme.colorScheme.onTertiaryContainer,
                    modifier = Modifier.padding(8.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(24.dp))
        Text("分析結果1(VirusTotal)", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onBackground)
        Card(modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {


                Text("評価: ${summary?.rating ?: "N/A"}", fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
                Text("検出率: ${summary?.positives ?: 0} / ${summary?.total ?: 0}")
                Text("最終分析: ${attributes?.lastAnalysisDate ?: "N/A"}")

                Text("検出された脅威の主な種類: ${category?.categoryName ?: "なし"}")
                Text("概要: ${category?.descripton ?: "なし"}")
                Text("リスクレベル: ${category?.risk_level ?: "なし"}")
                Text("主な動作:")
                if (category?.action != null) {
                    for (act in category.action) {
                        Text("・ $act")
                    }
                } else {
                    Text("なし")
                }
                Text("推奨される対策: ${category?.recommendation ?: "なし"}")

                // グラフ用のデータを作成
                val chartData = listOf(
                    ChartData(
                        value = attributes?.safe ?: 0,
                        color = Color(0xFF4CAF50), // Green
                        label = "安全"
                    ),
                    ChartData(
                        value = attributes?.suspicious ?: 0,
                        color = Color(0xFFFF9800), // Orange
                        label = "疑わしい"
                    ),
                    ChartData(
                        value = attributes?.malicious ?: 0,
                        color = Color(0xFFF44336), // Red
                        label = "悪意あり"
                    )
                )

                // グラフと凡例を横に並べて表示
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceAround // スペースを均等に配置
                ) {
                    DonutChart(data = chartData)
                    ChartLegend(data = chartData)
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        // --- urlscan.ioの結果 ---
        Text("分析結果2(urlscan.io)", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold,color = MaterialTheme.colorScheme.onBackground)
        Card(modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {

                val urlscan = uiState.urlResponse?.urlscan
                Text("評価: ${urlscan?.custom_rating ?: "N/A"}", fontSize = 18.sp, fontWeight = FontWeight.SemiBold)

                val task = uiState.urlResponse?.urlscan?.task

                val isotime = uiState.urlResponse?.urlscan?.task?.time
                // isotime が null でない場合のみ変換
                val jstString = isotime?.let {
                    val instant = Instant.parse(it)
                    val jstTime = instant.atZone(ZoneId.of("Asia/Tokyo"))
                    val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                    jstTime.format(formatter)
                } ?: ""  // null の場合の代替表示

                Text("最終分析: ${jstString}")
                Text("URL: ${task?.url}")

                val security_state_summary = uiState.urlResponse?.urlscan?.security_state_summary

                // グラフ用のデータを作成
                val chartData = listOf(
                    ChartData(
                        value = security_state_summary?.secure ?: 0,
                        color = Color(0xFF4CAF50), // Green
                        label = "安全"
                    ),
                    ChartData(
                        value = security_state_summary?.insecure ?: 0,
                        color = Color(0xFFFF9800), // Orange
                        label = "疑わしい"
                    ),
                    ChartData(
                        value = security_state_summary?.total ?: 0,
                        color = Color(0x44444444), // Gray
                        label = "不明"
                    )
                )

                // グラフと凡例を横に並べて表示
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceAround // スペースを均等に配置
                ) {
                    DonutChart(data = chartData)
                    ChartLegend(data = chartData)
                }

                // ▼▼▼ ここからが画像表示部分 ▼▼▼
                Text("スクリーンショット:")
                // URLから画像を非同期で読み込んで表示する
                AsyncImage(
                    model = task?.screenshotURL, // 表示したい画像のURL
                    contentDescription = "スキャン結果のスクリーンショット",
                    modifier = Modifier
                        .fillMaxWidth()
                        .aspectRatio(16f / 9f) // 16:9の比率で表示
                        .clickable { showDialog = true },
                    contentScale = ContentScale.Crop // 画像をコンポーネントに合わせて切り抜く
                )
                // ▲▲▲ ここまで ▲▲▲
            }
        }
    }
    if (showDialog) {
        Dialog(onDismissRequest = { showDialog = false }) {
            // ダイアログの中身。ここにもう一度AsyncImageを置いて拡大表示する
            AsyncImage(
                model = uiState.urlResponse?.urlscan?.task?.screenshotURL,
                contentDescription = "拡大スクリーンショット",
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}


@Composable
fun FileResultView(uiState: UiState, onConfirmSend: () -> Unit) {
    var showDialog by remember { mutableStateOf(false)}
    Column {
        Text("ファイルスキャン結果", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)

        Card(modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                val summary = uiState.fileResponse?.data?.summary
                val category = uiState.fileResponse?.data?.category
                val attributes = uiState.fileResponse?.data?.attributes

                Text("評価: ${summary?.rating ?: "N/A"}", fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
                Text("検出率: ${summary?.positives ?: 0} / ${summary?.total ?: 0}")
                Text("最終分析: ${uiState.fileResponse?.data?.attributes?.lastAnalysisDate ?: "N/A"}")

                // ここでファイル特有の情報も追加できる
                //Text("ファイル名: ${uiState.fileResponse?.data?.attributes?.fileName ?: "不明"}")
                //Text("SHA-256: ${uiState.fileResponse?.data?.attributes?.sha256 ?: "N/A"}")


                Text("検出された脅威の主な種類: ${category?.categoryName ?: "なし"}")
                Text("概要: ${category?.description ?: "なし"}")
                Text("リスクレベル: ${category?.risk_level ?: "なし"}")
                Text("主な動作:")
                if (category?.action != null) {
                    for (act in category.action) {
                        Text("・ $act")
                    }
                } else {
                    Text("なし")
                }
                Text("推奨される対策: ${category?.recommendation ?: "なし"}")

                // グラフ用のデータを作成
                val chartData = listOf(
                    ChartData(
                        value = attributes?.safe ?: 0,
                        color = Color(0xFF4CAF50), // Green
                        label = "安全"
                    ),
                    ChartData(
                        value = attributes?.undetected ?: 0,
                        color = Color(0xFF4CAF50), // Green
                        label = "未検出"
                    ),
                    ChartData(
                        value = attributes?.suspicious ?: 0,
                        color = Color(0xFFFF9800), // Orange
                        label = "疑わしい"
                    ),
                    ChartData(
                        value = attributes?.malicious ?: 0,
                        color = Color(0xFFF44336), // Red
                        label = "悪意あり"
                    )
                )


                // グラフと凡例を横に並べて表示
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceAround // スペースを均等に配置
                ) {
                    DonutChart(data = chartData)
                    ChartLegend(data = chartData)
                }

                if (summary?.rating == null) {
                    Text("このファイルはまだサーバーに登録されていません。")
                    Text("VirusTotalに送信して分析しますか？", fontWeight = FontWeight.SemiBold)
                    Button(
                        onClick = {showDialog = true},
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(50.dp),
                        // ファイルが選択されている場合のみ有効化

                    ) {
                        Icon(
                            imageVector = Icons.Default.Search,
                            contentDescription = null,
                            modifier = Modifier.size(ButtonDefaults.IconSize)
                        )
                        Spacer(Modifier.size(ButtonDefaults.IconSpacing))
                        Text("ファイルを送信してスキャン")
                    }
                }
            }
        }
    }

    if (showDialog) {
        AlertDialog(
            onDismissRequest = { showDialog = false },
            icon = {
                Icon(
                    imageVector = Icons.Default.Warning,
                    contentDescription = "警告",
                    tint = MaterialTheme.colorScheme.error
                )
            },
            title = {
                Text(
                    text = "ファイル送信の確認",
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.onSurface
                )
            },
            text = {
                Text(
                    text = "このファイルを送ると、第三者の目に触れる可能性があります。\nそれでも送信しますか？",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            },
            confirmButton = {
                TextButton(
                    onClick = { showDialog = false
                        onConfirmSend() }
                ) {
                    Text(
                        "送信する",
                        color = MaterialTheme.colorScheme.primary
                    )
                }
            },
            dismissButton = {
                TextButton(
                    onClick = { showDialog = false }
                ) {
                    Text(
                        "送信しない",
                        color = MaterialTheme.colorScheme.error
                    )
                }
            },
            containerColor = MaterialTheme.colorScheme.surface,
            tonalElevation = 2.dp,
            shape = MaterialTheme.shapes.extraLarge
        )
    }
}

// --- 各タブの中身となるComposable ---
@Composable
fun ScanUrlTab(value: String, onValueChange: (String) -> Unit, onScanClick: () -> Unit) {
    Column(
        // 画面の両端に16dpの余白を追加
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally // 中央揃え
    ) {
        // テキスト入力フィールド
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            modifier = Modifier.fillMaxWidth(), // 横幅を最大に
            label = { Text("評価したいURLを入力") },
            placeholder = { Text("https://example.com") },
            // 先頭に検索アイコンを表示
            leadingIcon = {
                Icon(
                    imageVector = Icons.Default.Search,
                    contentDescription = "検索アイコン"
                )
            },
            // 末尾にクリアボタンを表示（入力時のみ）
            trailingIcon = {
                if (value.isNotEmpty()) {
                    IconButton(onClick = { onValueChange("") }) {
                        Icon(
                            imageVector = Icons.Default.Clear,
                            contentDescription = "入力をクリア"
                        )
                    }
                }
            },
            singleLine = true // 入力を1行に制限
        )

        Spacer(modifier = Modifier.height(24.dp)) // ボタンとの間隔を少し広めに

        // スキャンボタン
        Button(
            onClick = onScanClick,
            modifier = Modifier
                .fillMaxWidth()
                .height(50.dp), // 高さを少し大きく
            // ボタンが押せる状態（URLが空でない）でのみ有効化
            enabled = value.isNotBlank()
        ) {
            // ボタン内のアイコンとテキストの間隔を調整
            Icon(
                imageVector = Icons.Default.Search,
                contentDescription = null, // ボタンテキストが説明を兼ねるためnull
                modifier = Modifier.size(ButtonDefaults.IconSize)
            )
            Spacer(Modifier.size(ButtonDefaults.IconSpacing))
            Text("URLをスキャン")
        }
    }
}

@Composable
fun ScanIpTab(value: String, onValueChange: (String) -> Unit, onScanClick: () -> Unit) {
    Column {
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            label = { Text("評価したいIPアドレスを入力") },
            placeholder = { Text("8.8.8.8") },
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(modifier = Modifier.height(16.dp))
        Button(onClick = onScanClick, modifier = Modifier.fillMaxWidth()) {
            Text("IPをスキャン")
        }
    }
}

@Composable
fun ScanHashTab(value: String, onValueChange: (String) -> Unit, onScanClick: () -> Unit) {
    Column {
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            label = { Text("評価したいファイルハッシュ(SHA256)を入力") },
            placeholder = { Text("275a021b...") },
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(modifier = Modifier.height(16.dp))
        Button(onClick = onScanClick, modifier = Modifier.fillMaxWidth()) {
            Text("ハッシュをスキャン")
        }
    }
}

@Composable
fun ScanFileTab(onScanClick: () -> Unit) {
    Button(onClick = onScanClick, modifier = Modifier.fillMaxWidth()) {
        Text("ファイルを選択してスキャン")
    }
}

@Composable
fun ScanFileTab2(
    selectedFileName: String?,
    onFileSelectClick: () -> Unit,
    onScanClick: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp), // 全体に余白
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // ファイル選択を促すUIエリア
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.medium, // 角を丸く
            tonalElevation = 2.dp // 少しだけ浮き上がらせる
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                // ファイルが選択されていない場合
                if (selectedFileName == null) {
                    Icon(
                        imageVector = Icons.Default.Description,
                        contentDescription = null,
                        modifier = Modifier.size(48.dp),
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "スキャンしたいファイルを\n選んでください",
                        style = MaterialTheme.typography.titleMedium,
                        textAlign = TextAlign.Center
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    // 控えめな見た目のボタン
                    FilledTonalButton(onClick = onFileSelectClick) {
                        Text("ファイルを選択")
                    }
                } else {
                    // ファイルが選択された場合
                    Icon(
                        imageVector = Icons.Default.CheckCircle,
                        contentDescription = null,
                        modifier = Modifier.size(48.dp),
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "ファイルが選択されました",
                        style = MaterialTheme.typography.titleMedium
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    // 選択されたファイル名を装飾
                    Text(
                        text = selectedFileName,
                        style = MaterialTheme.typography.bodyLarge,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis // 長いファイル名は省略
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        // スキャンボタン
        Button(
            onClick = onScanClick,
            modifier = Modifier
                .fillMaxWidth()
                .height(50.dp),
            // ファイルが選択されている場合のみ有効化
            enabled = selectedFileName != null
        ) {
            Icon(
                imageVector = Icons.Default.Search,
                contentDescription = null,
                modifier = Modifier.size(ButtonDefaults.IconSize)
            )
            Spacer(Modifier.size(ButtonDefaults.IconSpacing))
            Text("ファイルをスキャン")
        }
    }
}

fun queryFileName(context: Context, uri: Uri): String? {
    val cursor = context.contentResolver.query(uri, null, null, null, null)
    cursor?.use {
        if (it.moveToFirst()) {
            val nameIndex = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (nameIndex != -1) {
                return it.getString(nameIndex)
            }
        }
    }
    return null
}

fun calculateFileHash(context: Context, uri: Uri, algorithm: String = "SHA-256"): String? {
    return try {
        val digest = MessageDigest.getInstance(algorithm)
        context.contentResolver.openInputStream(uri)?.use { inputStream ->
            val buffer = ByteArray(8192)
            var bytesRead: Int
            while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                digest.update(buffer, 0, bytesRead)
            }
        }
        digest.digest().joinToString("") { "%02x".format(it) }
    } catch (e: Exception) {
        e.printStackTrace()
        null
    }
}


fun trimBeforeHttp(urlString: String?): String {
    if (urlString.isNullOrBlank()) return ""

    val index = urlString.indexOf("http")
    return if (index >= 0) {
        urlString.substring(index)
    } else {
        urlString // "http" がなければそのまま返す
    }
}


fun extractActualUrl(urlString: String?): String? {
    // URLがnullまたは空の場合は、空文字列を返す
    if (urlString.isNullOrBlank()) {
        return ""
    }

    // GoogleのリダイレクトURLか簡易的にチェック
    if (!urlString.contains("google")) {
        return trimBeforeHttp(urlString)
    }
    val url = trimBeforeHttp(urlString)
    return try {
        // 1. 文字列をUriオブジェクトに変換
        val uri = Uri.parse(url)
        // 2. "url"という名前のパラメータの値を取得
        val actualUrl = uri.getQueryParameter("url")
        // 3. 取得できた場合はその値を、できなかった場合は元のURLを返す
        actualUrl ?: url
    } catch (e: Exception) {
        // 不正なURL形式などでパースに失敗した場合
        url
    }
}

// 円グラフの各セクションのデータを保持するためのクラス
data class ChartData(
    val value: Int,
    val color: Color,
    val label: String
)

/**
 * 結果の内訳を示す円グラフ（ドーナツグラフ）を表示するComposable
 * @param data 表示するデータのリスト
 * @param size グラフ全体のサイズ
 * @param strokeWidth グラフの線の太さ
 */
@Composable
fun DonutChart(
    data: List<ChartData>,
    size: Dp = 120.dp,
    strokeWidth: Dp = 20.dp
) {
    val total = data.sumOf { it.value }.toFloat()
    if (total == 0f) return // データがない場合は表示しない

    // 描画用の角度を保持する変数
    var startAngle = -90f

    Canvas(modifier = Modifier.size(size)) {
        // データリストの各項目を円弧として描画
        data.forEach { item ->
            val sweepAngle = (item.value / total) * 360f
            drawArc(
                color = item.color,
                startAngle = startAngle,
                sweepAngle = sweepAngle,
                useCenter = false,
                style = Stroke(width = strokeWidth.toPx(), cap = StrokeCap.Butt)
            )
            startAngle += sweepAngle
        }
    }
}

/**
 * グラフの凡例を表示するComposable
 * @param data 表示するデータのリスト
 */
@Composable
fun ChartLegend(data: List<ChartData>) {
    Column {
        data.forEach { item ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                // 色の付いた四角
                Box(modifier = Modifier
                    .size(16.dp)
                    .background(item.color)
                )
                Spacer(modifier = Modifier.width(8.dp))
                // ラベルと数値
                Text("${item.label}: ${item.value}")
            }
        }
    }
}

@Composable
fun StartScreen(
    onStartClick: () -> Unit,
    onStartBrowserClick: () -> Unit, // ← 新しいボタン用の関数を追加
    onFeedbackClick: () -> Unit
) {
    // ダイアログを表示するかどうかの状態を管理 (初期値は false で非表示)
    var showTermsDialog by remember { mutableStateOf(false) }

    // もし showTermsDialog が true になったら、ダイアログを表示する
    if (showTermsDialog) {
        TermsOfServiceDialog(
            onDismiss = {
                // ダイアログの外側をタップした、または「閉じる」ボタンで非表示にする
                showTermsDialog = false
            }
        )
    }
    Scaffold(
        containerColor = MaterialTheme.colorScheme.background, // 画面全体の背景色
        topBar = { /* TopAppBar */ }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            // 中身
        }
    }
    BoxWithConstraints(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        val buttonHeight = maxHeight * 0.1f   // 画面全体の10%
        val space = maxHeight * 0.03f

        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(space)
        ) {
            Text(
                text = "セキュアチェッカー\nモバイル",
                style = MaterialTheme.typography.headlineLarge,
                color = MaterialTheme.colorScheme.primary,
                textAlign = TextAlign.Center
            )

            // --- スキャン開始ボタン ---
            Button(
                onClick = onStartClick,
                modifier = Modifier
                    .fillMaxWidth(0.8f)
                    .height(buttonHeight)   // 画面基準で高さ指定
            ) {
                Text(
                    "スキャンを開始する",
                    fontSize = (buttonHeight.value * 0.3).sp
                )
            }

            // --- ブラウザ開始ボタン ---
            Button(
                onClick = onStartBrowserClick,
                modifier = Modifier
                    .fillMaxWidth(0.8f)
                    .height(buttonHeight)   // 同じ高さ
            ) {
                Text(
                    "ブラウザを開始する",
                    fontSize = (buttonHeight.value * 0.3).sp
                )
            }
            Spacer(modifier = Modifier.height(32.dp))
            Button(
                onClick = onFeedbackClick,
                modifier = Modifier
                    .fillMaxWidth(0.8f)
                    .height(buttonHeight)   // 同じ高さ
            ) {
                Text(
                    "要望・フィードバック",
                    fontSize = (buttonHeight.value * 0.25).sp
                )
            }
            Spacer(modifier = Modifier.height(32.dp))
            BackToLoginButton(50.dp)
            // ボタンとの間にスペースを追加
            Spacer(modifier = Modifier.height(4.dp))

            // 利用規約ボタン (TextButtonで控えめな見た目に)
            TextButton(onClick = { showTermsDialog = true }) {
                Text("利用規約")
            }
        }
    }
}

class SecureWebViewClient(
    private val viewModel: SecureCheckerViewModel
) : WebViewClient() {
    override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
        val url = request?.url.toString()
        println("click saretayo:" + url)
        if (url.isNotBlank() && request?.hasGesture() == true) {
            // クリックされたURLでスキャンを開始
            println("touch")
            //viewModel.scanUrl(url)
            viewModel.test(url)
            println("zzzzzz")
            return false
        }


        println("important")
        return true
    }
}

@Composable
fun BackToLoginButton(buttonHeight: Dp) {
    val context = LocalContext.current  // ← Composable 内でのみ OK

    Button(
        onClick = {
            // セッションをクリアしてログイン画面へ
            SessionManager(context).clearToken()

            context.startActivity(
                Intent(context, LoginActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                }
            )
        },
        modifier = Modifier
            .fillMaxWidth(0.8f)
            .height(buttonHeight)
    ) {
        Text(
            "ログイン画面に戻る",
            fontSize = (buttonHeight.value * 0.3).sp
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SearchBoxScreen(
    query: String,
    onQueryChange: (String) -> Unit,
    onSearch: () -> Unit,
    onNavigateBack: () -> Unit
) {
    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = MaterialTheme.shapes.large,
                elevation = CardDefaults.cardElevation(defaultElevation = 6.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp)
                ) {
                    CenterAlignedTopAppBar(
                        title = {
                            Text(
                                text = "セキュアブラウザ",
                                style = MaterialTheme.typography.titleLarge,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                        },
                        navigationIcon = {
                            IconButton(onClick = onNavigateBack,) {
                                Icon(
                                    imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                                    contentDescription = "戻る",
                                    tint = MaterialTheme.colorScheme.onSurface
                                )
                            }
                        },
                        colors = TopAppBarDefaults.centerAlignedTopAppBarColors(
                            containerColor = Color.Transparent // Card内なので透明
                        )
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    OutlinedTextField(
                        value = query,
                        onValueChange = onQueryChange,
                        label = { Text("検索ワードを入力") },
                        modifier = Modifier.fillMaxWidth(),
                        trailingIcon = {
                            if (query.isNotEmpty()) {
                                IconButton(onClick = { onQueryChange("") }) {
                                    Icon(
                                        imageVector = Icons.Default.Clear,
                                        contentDescription = "クリア",
                                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        },
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = MaterialTheme.colorScheme.primary,
                            focusedLabelColor = MaterialTheme.colorScheme.primary
                        )
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    Button(
                        onClick = onSearch,
                        modifier = Modifier.fillMaxWidth(),
                        shape = MaterialTheme.shapes.medium
                    ) {
                        Text("検索")
                    }
                }
            }

            Spacer(modifier = Modifier.height(24.dp))


            Surface(
                shape = MaterialTheme.shapes.medium,
                color = MaterialTheme.colorScheme.secondaryContainer,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "検索の使い方",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSecondaryContainer
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "検索ワードを入力して「検索」ボタンを押すと、関連情報が表示されます。",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSecondaryContainer
                    )
                }
            }


        }
    }
}


@Composable
fun SecureWebView(viewModel: SecureCheckerViewModel, initialUrl: String, onNavigateBack: () -> Unit) {
    val uiState = viewModel.uiState.value
    val context = LocalContext.current
    var unsafeUrl by remember { mutableStateOf<String?>(null) }
    val urlToLoad = viewModel.approvedUrlToLoad.value


    var searchUrl by remember { mutableStateOf(initialUrl) }
    // 取得したURLを保持するための状態(state)を追加
    var clickedUrl by remember { mutableStateOf("") }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {




        // 取得したURLを表示するText Composable
        if (clickedUrl.isNotEmpty()) {
            Text(
                text = "クリックされたURL:",
                style = MaterialTheme.typography.titleMedium
            )
            Text(
                text = clickedUrl,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.primary
            )
            Spacer(modifier = Modifier.height(16.dp))
        }


        if (searchUrl.isNotEmpty()) {
            AndroidView(
                factory = { context ->
                    WebView(context).apply {
                        settings.javaScriptEnabled = true
                        webViewClient = SecureWebViewClient(viewModel)
                    }

                },
                update = { webView ->
                    println("update desu------------------")


                    // 優先度1：安全なURLを読み込む指示があるか？
                    if (urlToLoad != null) {
                        webView.loadUrl(urlToLoad)

                        println("asfdfdfdfdf")
                        //viewModel.onUrlLoaded()

                    }


                    // 優先度2：安全なURLの指示がなく、かつ現在のURLが検索結果と違うか？
                    else if (urlToLoad == null && webView.url != searchUrl) {
                        webView.loadUrl(searchUrl)
                        println("vvvvvvvvvvvvvvv")

                    }
                    else {}


                },
                modifier = Modifier.fillMaxSize()
            )
        }

        print("last")
    }



    unsafeUrl?.let { url ->
        UnsafeUrlDialog(
            url = url,
            onDismiss = { unsafeUrl = null },
            onProceed = {
                unsafeUrl = null
                // 自己責任でロード
                viewModel.urlText.value = url
            }
        )
    }
}

@Composable
fun UnsafeUrlDialog(
    url: String,
    onDismiss: () -> Unit,
    onProceed: () -> Unit
) {
    AlertDialog(
        onDismissRequest = { onDismiss() },
        title = { Text("警告") },
        text = { Text("このURLは危険と判定されました。\n自己責任でアクセスしますか？\n\n$url") },
        confirmButton = {
            TextButton(onClick = onProceed) {
                Text("自己責任でアクセス")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("戻る")
            }
        }
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SimpleWebView(
    url: String,
    viewModel: SecureCheckerViewModel,
    onNavigateBack: () -> Unit
) {
    val uiState by viewModel.uiState
    val approvedUrl by viewModel.approvedUrlToLoad
    val showErrorDialog by viewModel.showUrlValidationErrorDialog
    val urlStack = remember { mutableStateListOf<String>() }
    var isNavigatingBack by remember { mutableStateOf(false) }
    var showWebView by remember { mutableStateOf(false) }
    var webViewRef by remember { mutableStateOf<WebView?>(null) }

    val trustedDomains = listOf(
        "google.com",
        "google.co.jp",
        "yahoo.co.jp",
        "yahoo.com",
        "bing.com",
        "youtube.com",
        "nicovideo.jp",
        "dailymotion.com/jp",
        "twitch.tv",
        "rakuten.co.jp",
    )




    fun openUrl2() {
        val newUrl = viewModel.pendingUnsafeUrl.value ?: return
        if (urlStack.lastOrNull() != newUrl) {
            urlStack.add(newUrl)
        }
        viewModel.approvedUrlToLoad.value = newUrl  // このタイミングで初めてセット
        showWebView = true
    }

    fun openUrl(Url: String?) {
        val newUrl = Url ?: return
        if (urlStack.lastOrNull()?.substringAfter(".") != newUrl.substringAfter(".")) {
            urlStack.add(newUrl)
        }
        viewModel.approvedUrlToLoad.value = newUrl
        showWebView = true
    }

    fun isTrustedUrl(checkUrl: String): Boolean {
        openUrl(checkUrl)
        return trustedDomains.any { checkUrl.contains(it) }
    }

    fun handleBack() {
        if (urlStack.isNotEmpty()) {
            urlStack.removeAt(urlStack.lastIndex)
            if (urlStack.isNotEmpty()) {
                viewModel.approvedUrlToLoad.value = urlStack.last()
                showWebView = true
            } else {
                // すべて削除された場合
                urlStack.clear()
                showWebView = false
                viewModel.resetAllStates()   // ← これでUIをクリア
                onNavigateBack()
            }
        } else {
            urlStack.clear()
            showWebView = false
            viewModel.resetAllStates()      // ← これで「安全です」UIも消える
            onNavigateBack()
        }
    }


    LaunchedEffect(url) {
        if (isTrustedUrl(url)) {
            viewModel.approvedUrlToLoad.value = url
        } else {
            viewModel.scanUrl(url)
        }
    }


    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("セキュアブラウザ") },
                navigationIcon = {
                    Row {
                        IconButton(
                            onClick = {
                                viewModel.resetAllStates()
                                handleBack()
                            }
                        ) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                                contentDescription = "戻る"
                            )
                        }
                        IconButton(
                            onClick = {
                                onNavigateBack() // ホームまで戻る
                            }
                        ) {
                            Icon(
                                imageVector = Icons.Default.Home,
                                contentDescription = "ホームに戻る"
                            )
                        }

                    }
                }
            )
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            when {
                uiState.isLoading -> {
                    Column(
                        modifier = Modifier.align(Alignment.Center),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        CircularProgressIndicator()
                        Spacer(modifier = Modifier.height(16.dp))
                        Text("URLの安全性を確認中...")
                    }
                }

                uiState.error == "unsafe" -> {
                    val summary = uiState.urlResponse?.virustotal?.data?.summary
                    val attributes = uiState.urlResponse?.virustotal?.data?.attributes
                    val category = uiState.urlResponse?.virustotal?.data?.category
                    val task = uiState.urlResponse?.urlscan?.task
                    Column(
                        modifier = Modifier
                            .align(Alignment.Center)
                            .padding(16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = "このURLは安全ではない可能性があります",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.error
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Button(
                            onClick = {
                                openUrl2()
                                viewModel.reset()
                            },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.error
                            )
                        ) {
                            Text("表示する")
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        Button(
                            onClick = {
                                viewModel.resetAllStates()
                                handleBack()
                            },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.error
                            )
                        ) {
                            Text("戻る")
                        }
                        Card(modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text(
                                    text = uiState.urlResponse?.target ?: "URLがありません",
                                    style = MaterialTheme.typography.bodyLarge,
                                    // 変更点: onTertiaryContainer を指定して文字色を最適化
                                    color = MaterialTheme.colorScheme.onTertiaryContainer,
                                    modifier = Modifier.padding(8.dp)
                                )
                                Text(
                                    "評価: ${summary?.rating ?: "N/A"}",
                                    fontSize = 18.sp,
                                    fontWeight = FontWeight.SemiBold
                                )
                                Text("検出率: ${summary?.positives ?: 0} / ${summary?.total ?: 0}")
                                Text("最終分析: ${attributes?.lastAnalysisDate ?: "N/A"}")

                                Text("検出された脅威の主な種類: ${category?.categoryName ?: "なし"}")
                                Text("概要: ${category?.descripton ?: "なし"}")
                                Text("リスクレベル: ${category?.risk_level ?: "なし"}")
                                Text("主な動作:")
                                if (category?.action != null) {
                                    for (act in category.action) {
                                        Text("・ $act")
                                    }
                                } else {
                                    Text("なし")
                                }
                                AsyncImage(
                                    model = task?.screenshotURL, // 表示したい画像のURL
                                    contentDescription = "スキャン結果のスクリーンショット",
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .aspectRatio(16f / 9f),
                                    contentScale = ContentScale.Crop // 画像をコンポーネントに合わせて切り抜く
                                )
                            }
                        }

                    }
                }

                uiState.error != null && uiState.error != "unsafe" && uiState.error != "safe" -> {
                    Column(
                        modifier = Modifier
                            .align(Alignment.Center)
                            .padding(16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = "エラー",
                            style = MaterialTheme.typography.titleLarge,
                            color = MaterialTheme.colorScheme.error
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = uiState.error ?: "",
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Button(onClick = {
                            handleBack()
                        }) {
                            Text("戻る")
                        }
                    }
                }

                uiState.error == "safe" -> {
                    val summary = uiState.urlResponse?.virustotal?.data?.summary
                    val attributes = uiState.urlResponse?.virustotal?.data?.attributes
                    val category = uiState.urlResponse?.virustotal?.data?.category
                    val task = uiState.urlResponse?.urlscan?.task
                    Column(
                        modifier = Modifier
                            .align(Alignment.Center)
                            .padding(16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = "このURLは安全だと判定されました",
                            style = MaterialTheme.typography.titleMedium,
                            color = Color(0xFF4CAF50)
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Button(
                            onClick = {
                                openUrl2()
                                viewModel.reset()
                            },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.primary
                            )
                        ) {
                            Text("表示する")
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        Button(
                            onClick = {
                                viewModel.resetAllStates()
                                handleBack()
                            },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.primary
                            )
                        ) {
                            Text("戻る")
                        }
                        Card(modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text(
                                    text = uiState.urlResponse?.target ?: "URLがありません",
                                    style = MaterialTheme.typography.bodyLarge,
                                    // 変更点: onTertiaryContainer を指定して文字色を最適化
                                    color = MaterialTheme.colorScheme.onTertiaryContainer,
                                    modifier = Modifier.padding(8.dp)
                                )
                                Text("評価: ${summary?.rating ?: "N/A"}", fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
                                Text("検出率: ${summary?.positives ?: 0} / ${summary?.total ?: 0}")
                                Text("最終分析: ${attributes?.lastAnalysisDate ?: "N/A"}")

                                Text("検出された脅威の主な種類: ${category?.categoryName ?: "なし"}")
                                Text("概要: ${category?.descripton ?: "なし"}")
                                Text("リスクレベル: ${category?.risk_level ?: "なし"}")
                                AsyncImage(
                                    model = task?.screenshotURL, // 表示したい画像のURL
                                    contentDescription = "スキャン結果のスクリーンショット",
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .aspectRatio(16f / 9f),
                                    contentScale = ContentScale.Crop // 画像をコンポーネントに合わせて切り抜く
                                )
                            }
                        }
                    }
                }

                approvedUrl != null -> {
                    BackHandler {
                        handleBack()
                    }
                    AndroidView(
                        modifier = Modifier.fillMaxSize(),
                        factory = { context ->
                            AdBlocker.init(context)
                            WebView(context).apply {
                                webViewRef = this
                                settings.javaScriptEnabled = true
                                loadUrl(approvedUrl ?: url)
                                webViewClient = object : WebViewClient() {
                                    override fun shouldOverrideUrlLoading(
                                        view: WebView?,
                                        request: WebResourceRequest?
                                    ): Boolean {
                                        val clickedUrl = request?.url?.toString() ?: return false
                                        if (isTrustedUrl(clickedUrl)) {
                                            view?.loadUrl(clickedUrl)
                                        } else {
                                            viewModel.scanUrl(clickedUrl)
                                        }
                                        return true
                                    }

                                    override fun shouldInterceptRequest(
                                        view: WebView?,
                                        request: WebResourceRequest?
                                    ): WebResourceResponse? {
                                        val requestUrl = request?.url.toString()
                                        return if (AdBlocker.isAd(requestUrl)) {
                                            WebResourceResponse(
                                                "text/plain",
                                                "utf-8",
                                                ByteArrayInputStream("".toByteArray())
                                            )
                                        } else {
                                            super.shouldInterceptRequest(view, request)
                                        }
                                    }
                                }
                            }
                        },
                        update = { webView ->
                            approvedUrl?.let { webView.loadUrl(it) }
                        }
                    )
                }

                else -> {
                    Column(
                        modifier = Modifier
                            .align(Alignment.Center)
                            .padding(16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = "このURLは安全ではない可能性があります",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.error
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Button(
                            onClick = {
                                openUrl(url)
                            },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.error
                            )
                        ) {
                            Text("表示する")
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        Button(
                            onClick = {
                                onNavigateBack()
                                viewModel.resetAllStates()
                                      },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.error
                            )
                        ) {
                            Text("戻る")
                        }
                    }
                }
            }
        }
    }

    if (showErrorDialog) {
        AlertDialog(
            onDismissRequest = {
                viewModel.dismissUrlValidationErrorDialog()
                onNavigateBack()
            },
            title = { Text("無効なURL") },
            text = { Text("正しい形式のURLを入力してください。") },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.dismissUrlValidationErrorDialog()
                    onNavigateBack()
                }) {
                    Text("OK")
                }
            }
        )
    }
}


@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FeedbackScreen(
    onNavigateBack: () -> Unit, // 戻るための関数
    onSendFeedback: (String) -> Unit // 送信するための関数
) {
    // 入力されたテキストを保持するための状態
    var feedbackText by remember { mutableStateOf("") }
    val maxChars = 200 // 最大文字数を定義

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("ご意見・ご要望") },
                navigationIcon = {
                    // 戻るボタン
                    IconButton(onClick = onNavigateBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "スタート画面に戻る"
                        )
                    }
                }
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(16.dp) // 内側の余白
        ) {
            Text(
                "サービスの改善のため、皆様からのご意見をお待ちしております。",
                style = MaterialTheme.typography.bodyLarge
            )
            Spacer(modifier = Modifier.height(16.dp))

            // 複数行入力できるテキストフィールド
            OutlinedTextField(
                value = feedbackText,
                onValueChange = { newText ->
                    // 入力された文字数が上限を超えていなければ更新する
                    if (newText.length <= maxChars) {
                        feedbackText = newText
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                label = { Text("フィードバックを入力してください") },
                placeholder = { Text("ここに具体的な内容をご記入ください。") },
                // 文字数カウンターを表示する
                supportingText = {
                    Text(
                        text = "${feedbackText.length} / $maxChars",
                        modifier = Modifier.fillMaxWidth(),
                        textAlign = TextAlign.End // 右揃えで表示
                    )
                },
                // 文字数が上限に達したらエラー状態として表示（カウンターが赤色になるなど）
                isError = feedbackText.length == maxChars
            )


            Spacer(modifier = Modifier.height(16.dp))

            // 送信ボタン
            Button(
                onClick = { onSendFeedback(feedbackText) },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp),
                // テキストが入力されている場合のみボタンを有効化
                enabled = feedbackText.isNotBlank()
            ) {
                Text("送信する")
            }
        }
    }
}

//利用規約
@Composable
fun TermsOfServiceDialog(onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        // ダイアログのタイトル
        title = {
            Text("利用規約")
        },
        // ダイアログの本文
        text = {
            // 長い文章でもスクロールできるようにする
            Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                // ▼▼▼ ここに実際の利用規約のテキストを記述します ▼▼▼
                Text(
                    "本利用規約（以下、「本規約」といいます。）は、「セキュアチェッカーモバイル」（以下、「本アプリ」といいます。）の利用に関する条件を定めるものです。本アプリをご利用になる前によくお読みいただき、ご同意の上でご利用ください。\n\n" +

                            "第1条（本規約への同意）\n" +
                            "利用者は、本アプリをインストール、または利用を開始した時点で、本規約に同意したものとみなします。\n" +
                            "本規約に同意いただけない場合、利用者は本アプリを利用することはできません。\n\n" +

                            "第2条（サービスの概要）\n" +
                            "1. 本アプリは、利用者が入力または共有したURL、ファイル（以下、「スキャン対象データ」といいます。）の安全性を評価するための情報を提供するアプリケーションです。\n" +
                            "2. 本アプリは、第三者のセキュリティサービス（VirusTotal, urlscan.ioなど）のAPIを利用して、スキャン対象データの評価結果を表示します。\n" +
                            "3. 本アプリは、検索機能およびセキュアブラウザ機能を提供します。セキュアブラウザは、遷移先のURLの安全性を評価し、安全でない可能性があると判定された場合に警告を表示することがあります。\n\n" +

                            "第3条（禁止事項）\n" +
                            "利用者は、本アプリの利用にあたり、以下の行為を行ってはなりません。\n" +
                            " (1) 法令または公序良俗に違反する行為\n" +
                            " (2) 犯罪行為に関連する行為\n" +
                            " (3) 本アプリのサーバーまたはネットワークの機能を破壊したり、妨害したりする行為\n" +
                            " (4) 本アプリのサービスの運営を妨害するおそれのある行為\n" +
                            " (5) 他の利用者に関する個人情報等を収集または蓄積する行為\n" +
                            " (6) 不正な目的を持って本アプリを利用する行為\n" +
                            " (7) 本アプリの他の利用者またはその他の第三者に不利益、損害、不快感を与える行為\n" +
                            " (8) リバースエンジニアリング、逆コンパイル、または逆アセンブルする行為\n" +
                            " (9) その他、開発者が不適切と判断する行為\n\n" +

                            "第4条（知的財産権）\n" +
                            "本アプリに関する著作権、商標権その他一切の知的財産権は、開発者または開発者にライセンスを許諾している者に帰属します。利用者は、法令で認められる範囲を超えて、これらの知的財産権を侵害する行為を行ってはなりません。\n\n" +

                            "第5条（免責事項）\n" +
                            "1. 本アプリが提供する情報の正確性について\n" +
                            "本アプリが表示するスキャン結果は、第三者のセキュリティサービスから提供される情報に基づくものであり、開発者はその情報の正確性、完全性、信頼性、最新性を一切保証するものではありません。評価結果はあくまで参考情報としてご利用ください。\n" +
                            "2. セキュリティの保証について\n" +
                            "本アプリは、いかなるマルウェア、ウイルス、フィッシングサイト等の脅威からも利用者のデバイスを完全に保護することを保証するものではありません。「安全」と表示された場合でも、その対象が100%安全であることを保証するものではなく、最終的な判断は利用者自身の責任で行うものとします。\n" +
                            "3. 損害について\n" +
                            "本アプリの利用に際し、利用者に生じたいかなる損害（スキャン対象データの誤判定、サービスの停止、ウイルス感染、データの損失、逸失利益などを含むがこれらに限定されない）についても、開発者は一切の責任を負わないものとします。\n" +
                            "4. 第三者サービスについて\n" +
                            "本アプリが利用する第三者のAPIサービス（VirusTotal, urlscan.ioなど）は、予告なく仕様が変更されたり、停止したりする可能性があります。これにより本アプリの機能の一部または全部が利用できなくなった場合でも、開発者は責任を負いません。\n" +
                            "5. スキャン対象データについて\n" +
                            "利用者がスキャンしたURLやファイルは、分析のために第三者のセキュリティサービスに送信されます。機密情報や個人情報を含むURL・ファイルをスキャンする際は、利用者自身の責任で判断してください。開発者は、送信されたデータに関して一切の責任を負いません。\n\n" +

                            "第6条（サービスの変更・中断・終了）\n" +
                            "開発者は、利用者に通知することなく、本アプリの内容を変更し、または本アプリの提供を中止・終了することができるものとします。\n" +
                            "開発者は、本条に基づき開発者が行った措置に基づき利用者に生じた損害について、一切の責任を負いません。\n\n" +

                            "第7条（利用規約の変更）\n" +
                            "開発者は、必要と判断した場合には、利用者に通知することなくいつでも本規約を変更することができるものとします。変更後の利用規約は、本アプリ内に掲示した時点からその効力を生じるものとし、利用者が本規約の変更後も本アプリを使い続けた場合、変更後の規約に同意したものとみなします。\n\n" +

                            "第8条（準拠法・裁判管轄）\n" +
                            "本規約の解釈にあたっては、日本法を準拠法とします。\n" +
                            "本アプリに関して紛争が生じた場合には、開発者の所在地を管轄する裁判所を専属的合意管轄とします。"

                )
            }
        },
        // ダイアログのボタン
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("閉じる")
            }
        }
    )
}


@Preview(
    name = "Light Mode",
    showBackground = true
)
@Composable
fun SearchBoxScreenPreview() {
    MaterialTheme {
        SearchBoxScreen(
            query = "テスト",
            onQueryChange = {},
            onSearch = {},
            onNavigateBack = {}
        )
    }
}

