# app/api/analysis.py 
import requests
import hashlib
import base64
from flask import current_app
from datetime import datetime, timedelta
import time
from collections import OrderedDict
import sys

MAX_AGE_DAYS = 180  # 半年（変数）

# --- ヘルパー関数群 ---

def translate_result(result_text):
    """セキュリティベンダーの判定結果を日本語に翻訳する"""
    TRANSLATIONS = {
        "harmless": "無害", "malicious": "悪意あり", "suspicious": "疑わしい",
        "undetected": "未検出", "timeout": "タイムアウト","unrated":"判定不可","failure":"失敗","type-unsupported":"非対応"
    }
    if result_text is None: return "N/A"
    return TRANSLATIONS.get(result_text.lower(), result_text)

def calculate_custom_VTrating(stats, reputation):
    """あなたの評価ロジックを元にした、VTカスタム評価関数"""
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless = stats.get("harmless", 0)

    total = malicious + suspicious + harmless + undetected

    if total == 0: return "⚪️ 判定不可"

    significant_count = malicious + suspicious
    rating_score = 0

    if reputation is not None and reputation > 0:
        if significant_count == 0: rating_score = 1
        elif significant_count <= 2: rating_score = 2
        elif significant_count <= 5: rating_score = 3
        else: rating_score = 4
    elif reputation is not None and reputation < 0:
        if significant_count == 0: rating_score = 2
        elif significant_count <= 2: rating_score = 3
        else: rating_score = 4
    else:
        if significant_count == 0: rating_score = 1
        elif significant_count <= 2: rating_score = 2
        elif significant_count <= 5: rating_score = 3
        else: rating_score = 4

    if rating_score == 1: return "🟢 安全"
    if rating_score == 2: return "🟡 注意"
    if rating_score == 3: return "🟠 疑わしい"
    if rating_score >= 4: return "🔴 危険"
    return "⚪️ 判定不可"

def calculate_custom_URLrating(urlscan_data):
    # --- verdictsの抽出 ---
    verdicts = urlscan_data.get("verdicts", {})

    # --- response部分からsecurityStateを再帰的に取得 ---
    def collect_security_states(obj, results):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == "securityState":
                    if v == "secure":
                        results.append("secure")
                    elif v == "insecure":
                        results.append("insecure")
                    else:
                        results.append("unknown")
                else:
                    collect_security_states(v, results)
        elif isinstance(obj, list):
            for item in obj:
                collect_security_states(item, results)

    security_states = []
    if urlscan_data:
        collect_security_states(urlscan_data.get("data", {}), security_states)

    # --- securityState のカウント ---
    secure = security_states.count("secure")
    insecure = security_states.count("insecure")
    unknown = security_states.count("unknown")
    total_states = len(security_states)

    # --- 判定の初期化 ---
    rating = "⚪️ 判定不可"

    # --- 1. verdicts内に malicious=True があれば即危険 ---
    for section, v in verdicts.items():
        if isinstance(v, dict) and v.get("malicious", False):
            rating = "🔴 危険-1"
            break

    # --- 2. securityState割合判定 ---
    if rating == "⚪️ 判定不可" and total_states > 0:
        insecure_ratio = insecure / total_states
        percent = round(insecure_ratio * 100, 1)
        if insecure_ratio >= 0.2:
            rating = f"🔴 危険-2 ({percent}%)"
        elif insecure_ratio >= 0.1:
            rating = f"🟠 疑わしい-1 ({percent}%)"

    # --- 3. verdictsスコアベース（上書きしない） ---
    if rating == "⚪️ 判定不可":
        overall_score = verdicts.get("overall", {}).get("score", 0)
        urlscan_score = verdicts.get("urlscan", {}).get("score", 0)
        engines_score = verdicts.get("engines", {}).get("score", 0)

        if overall_score == 0 and urlscan_score == 0 and engines_score == -100:
            rating = "🟢 安全"
        elif overall_score <= 10 and urlscan_score <= 10 and engines_score <= -70:
            rating = "🟡 注意"
        elif overall_score <= 30 and urlscan_score <= 30 and engines_score <= -50:
            rating = "🟠 疑わしい"
        elif overall_score >= 30 and urlscan_score >= 30 and engines_score >= -50:
            rating = "🔴 危険"

    # --- 返却値を辞書形式で統合 ---
    return {
        "rating": rating,
        "security_state_summary": {
            "secure": secure,
            "insecure": insecure,
            "unknown": unknown,
            "total": total_states
        }
    }

def interpret_behavior(malware_type):
    behavior_descriptions = {
        "virus": {
            "name": "ウイルス",
            "description": "自己複製し、感染したファイルやシステムを変更します。",
            "actions": [
                "起動や動作速度の低下",
                "警告メッセージの表示",
                "データの破壊・削除",
            ],
            "risk_level": "高",
            "recommendation": "不審なファイルを削除し、システム全体をスキャンしてください。",
        },
        "trojan": {
            "name": "トロイの木馬",
            "description": "正当なソフトウェアを装い、システムに侵入後、不正な操作を行います。",
            "actions": [
                "外部からのリモートアクセスを許可",
                "システム設定の改変",
                "機密情報の窃取",
            ],
            "risk_level": "高",
            "recommendation": "不審なファイルを削除し、システム全体をスキャンしてください。",
        },
        "worm": {
            "name": "ワーム",
            "description": "ネットワークを通じて自己複製し、システム全体に感染を広げます。",
            "actions": [
                "自己複製と拡散",
                "ネットワークトラフィックの増加",
                "システムリソースの消耗",
            ],
            "risk_level": "中",
            "recommendation": "感染拡大を防ぐためにネットワークを監視し、感染源を除去してください。",
        },
        "ransomware": {
            "name": "ランサムウェア",
            "description": "システム内のファイルを暗号化し、復号化のために身代金を要求します。",
            "actions": [
                "ファイルの暗号化",
                "ランサムメッセージの表示",
                "暗号鍵の外部サーバ送信",
            ],
            "risk_level": "非常に高い",
            "recommendation": "直ちにネットワークを切断し、バックアップからシステムを復旧してください。",
        },
        "spyware": {
            "name": "スパイウェア",
            "description": "ユーザーの活動を密かに監視し、機密情報を収集します。",
            "actions": [
                "キーストロークの記録",
                "スクリーンショットの撮影",
                "ブラウジング履歴の収集",
            ],
            "risk_level": "高",
            "recommendation": "スパイウェアの駆除ツールを使用して、システム全体をスキャンしてください。",
        },
        "adware": {
            "name": "アドウェア",
            "description": "不要な広告を表示し、ユーザーの操作を妨げます。",
            "actions": [
                "広告の表示",
                "ブラウザのリダイレクト",
                "ユーザーのクリック行動の追跡",
            ],
            "risk_level": "低",
            "recommendation": "信頼できるアンチウイルスソフトを使用して、アドウェアを削除してください。",
        },
        "backdoor": {
            "name": "バックドア",
            "description": "攻撃者がシステムに密かにアクセスできるようにする不正な入口を作ります。",
            "actions": [
                "リモートアクセスの確立",
                "機密情報の窃取",
                "システム設定の変更",
            ],
            "risk_level": "高",
            "recommendation": "システムのセキュリティ設定を見直し、不審なプロセスやポートを確認してください。",
        },
        "rootkit": {
            "name": "ルートキット",
            "description": "システムに深く潜伏し、不正な操作を隠蔽します。",
            "actions": [
                "システム権限の奪取",
                "ログの改ざん",
                "アンチウイルスソフトの無効化",
            ],
            "risk_level": "非常に高い",
            "recommendation": "専門的なツールを使用して、システム全体をクリーンアップしてください。",
        },
        "bot": {
            "name": "ボット",
            "description": "システムをリモートで操作可能な状態にし、ボットネットの一部として使用します。",
            "actions": [
                "スパムメールの送信",
                "DDoS攻撃への参加",
                "リモートコマンドの実行",
            ],
            "risk_level": "高",
            "recommendation": "ネットワークトラフィックを監視し、不審な動作を検出してください。",
        },
        "keylogger": {
            "name": "キーロガー",
            "description": "ユーザーのキーストロークを記録し、入力されたデータを窃取します。",
            "actions": [
                "キーストロークの記録",
                "ログイン情報の窃取",
                "機密データの送信",
            ],
            "risk_level": "高",
            "recommendation": "アンチスパイウェアツールを使用して、キーロガーを検出および削除してください。",
        },
        "dropper": {
            "name": "ドロッパー",
            "description": "他のマルウェアをシステムに感染させます。",
            "actions": [
                "セキュリティのバイパス",
                "リモートアクセス",
                "データの破損や暗号化",
            ],
            "risk_level": "高",
            "recommendation": "感染が疑われるファイルやプロセスを隔離し、システムをネットワークから切断して、システムをスキャンしてください。",
        },
        "exploit": {
            "name": "エクスプロイト",
            "description": "システムやソフトウェアの脆弱性を悪用して、不正な操作を行います。",
            "actions": ["脆弱性の悪用", "システムのクラッシュ", "不正なコードの実行"],
            "risk_level": "非常に高い",
            "recommendation": "システムやソフトウェアを最新の状態に保ち、脆弱性を修正してください。",
        },
        "phishing": {
            "name": "フィッシング",
            "description": "偽のウェブサイトやメッセージを使用して、ユーザーの個人情報を詐取します。",
            "actions": [
                "偽のログインページへの誘導",
                "個人情報の窃取",
                "偽装メッセージの送信",
            ],
            "risk_level": "中",
            "recommendation": "不審なリンクをクリックしないよう注意し、二要素認証を設定してください。",
        },
        "malware": {
            "name": "マルウェア",
            "description": "コンピュータやネットワークに悪影響を及ぼすプログラム",
            "actions": ["データの損失と暗号化", "個人情報の窃取", "システムの制御喪失"],
            "risk_level": "非常に高い",
            "recommendation": "感染が疑われるファイルやプロセスを隔離し、システムをネットワークから切断して、システムをスキャンしてください。",
        },
        "xss": {
            "name": "クロスサイトスクリプティング",
            "description": "ユーザーのブラウザで悪意のあるスクリプトを実行させるための脆弱性を持つサイトです。",
            "actions": [
                "個人情報の窃取",
                "ウェブアプリケーションの改ざん",
                "フィッシング攻撃",
            ],
            "risk_level": "中",
            "recommendation": "影響を受けたシステムをネットワークから切断し、システムをスキャンしてください。",
        },
        "fraud": {
            "name": "詐欺",
            "description": "ユーザーを騙して金銭を詐取します。",
            "actions": ["偽のセキュリティ警告の表示", "金銭の詐取"],
            "risk_level": "低",
            "recommendation": "偽の警告を無視し、信頼できるセキュリティソフトを使用してください。",
        },
        "scareware": {
            "name": "スケアウェア",
            "description": "偽の警告を表示し、不要なソフトウェアを購入させようとします。",
            "actions": [
                "偽のセキュリティ警告の表示",
                "不正なソフトウェアのインストール促進",
                "金銭の詐取",
            ],
            "risk_level": "低",
            "recommendation": "偽の警告を無視し、信頼できるセキュリティソフトを使用してください。",
        },
        "cryptominer": {
            "name": "クリプトマイナー",
            "description": "システムのリソースを使用して、仮想通貨を不正に採掘します。",
            "actions": [
                "CPU/GPUのリソース消耗",
                "システムのパフォーマンス低下",
                "電力消費の増加",
            ],
            "risk_level": "中",
            "recommendation": "不審なプロセスを停止し、システムをスキャンしてください。",
        },
        "pup": {
            "name": "PUP（望ましくない可能性のあるプログラム）",
            "description": "ユーザーが意図せずにインストールした、不要なソフトウェアです。",
            "actions": [
                "ブラウザ設定の変更",
                "広告の表示",
                "システムパフォーマンスの低下",
            ],
            "risk_level": "低",
            "recommendation": "不要なソフトウェアを削除し、ブラウザ設定をリセットしてください。",
        },
        "c2": {
            "name": "c2",
            "description": "攻撃者が感染したコンピュータをリモートで操作するために使用します。",
            "actions": ["リモート操作", "データの流出", "ネットワーク内の拡張"],
            "risk_level": "高",
            "recommendation": "感染が疑われるファイルやプロセスを隔離し、システムをネットワークから切断して、システムをスキャンしてください。",
        },
        "riskware": {
            "name": "リスクウェア",
            "description": "意図的に悪意のあるソフトウェアではなく、通常のソフトウェアやツールであっても、セキュリティリスクを引き起こす可能性があるプログラムです。",
            "actions": [
                "データ漏洩",
                "セキュリティホールの悪用",
                "システムのパフォーマンス低下",
            ],
            "risk_level": "高",
            "recommendation": "システムをスキャンしてください。",
        },
        "spam": {
            "name": "スパム",
            "description": "不審なファイルやURL",
            "actions": ["フィッシング詐欺", "マルウェアの配布", "リソースの消費"],
            "risk_level": "中",
            "recommendation": "システムをスキャンしてください。",
        },
        "drive-by download": {
            "name": "ドライブバイダウンロード",
            "description": "ユーザーが意図せずにマルウェアをダウンロードさせます。",
            "actions": [
                "マルウェアの感染",
                "個人情報の漏洩",
                "ネットワークのセキュリティリスク",
            ],
            "risk_level": "高",
            "recommendation": "感染が疑われるファイルやプロセスを隔離し、システムをネットワークから切断して、システムをスキャンしてください。",
        },
        "rat": {
            "name": "リモートアクセスツール",
            "description": "リモートでユーザーのコンピュータにアクセスするためのツールをダウンロードさせます。",
            "actions": ["データの窃取", "システムの完全な制御", "監視とスパイ行為"],
            "risk_level": "中",
            "recommendation": "システムをスキャンしてください。",
        },
        "something threat": {
            "name": "何らかの脅威",
            "description": "このファイルの動作は不明です。",
            "actions": ["不明"],
            "risk_level": "不明",
            "recommendation": "専門家に相談してください。",
        },
        "unknown": {
            "name": "なし",
            "description": "安全な可能性が高いです。",
            "actions": ["なし"],
            "risk_level": "低",
            "recommendation": "なし",
        },
    }
    return behavior_descriptions.get(malware_type, behavior_descriptions["unknown"])


# マルウェアタイプの分析
def interpret_results(result):
    sum = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    malware_type = [
        "virus",
        "trojan",
        "worm",
        "ransomware",
        "spyware",
        "adware",
        "backdoor",
        "rootkit",
        "bot",
        "keylogger",
        "dropper",
        "exploit",
        "phishing",
        "xss",
        "fraud",
        "scareware",
        "cryptominer",
        "pup",
        "c2",
        "riskware",
        "spam",
        "drive-by download",
        "rat",
        "malware",
        "something threat",
        "unknown",
    ]
    for engine, details in result.items():
        if details["result"] and details["result"].lower().find("virus") >= 0:
            sum[0] = sum[0] + 1
        elif details["result"] and details["result"].lower().find("trojan") >= 0:
            sum[1] = sum[1] + 1
        elif details["result"] and details["result"].lower().find("worm") >= 0:
            sum[2] = sum[2] + 1
        elif details["result"] and details["result"].lower().find("ransomware") >= 0:
            sum[3] = sum[3] + 1
        elif details["result"] and (
            details["result"].lower().find("spyware") >= 0
            or "data harvesting" in details["result"].lower()
            or "information theft" in details["result"].lower()
        ):
            sum[4] = sum[4] + 1
        elif details["result"] and (
            details["result"].lower().find("adware") >= 0
            or "advertising" in details["result"].lower()
        ):
            sum[5] = sum[5] + 1
        elif details["result"] and details["result"].lower().find("backdoor") >= 0:
            sum[6] = sum[6] + 1
        elif details["result"] and details["result"].lower().find("rootkit") >= 0:
            sum[7] = sum[7] + 1
        elif details["result"] and details["result"].lower().find("bot") >= 0:
            sum[8] = sum[8] + 1
        elif details["result"] and details["result"].lower().find("keylogger") >= 0:
            sum[9] = sum[9] + 1
        elif details["result"] and details["result"].lower().find("dropper") >= 0:
            sum[10] = sum[10] + 1
        elif details["result"] and details["result"].lower().find("exploit") >= 0:
            sum[11] = sum[11] + 1
        elif details["result"] and (
            details["result"].lower().find("phishing") >= 0
            or details["result"].lower().find("fraudulent") >= 0
            or "fake site" in details["result"].lower()
        ):
            sum[12] = sum[12] + 1
        elif details["result"] and details["result"].lower().find("xss") >= 0:
            sum[13] = sum[13] + 1
        elif details["result"] and (
            details["result"].lower().find("fraud") >= 0
            or details["result"].lower().find("scam") >= 0
        ):
            sum[14] = sum[14] + 1
        elif details["result"] and details["result"].lower().find("scareware") >= 0:
            sum[15] = sum[15] + 1
        elif details["result"] and (
            details["result"].lower().find("crypto") >= 0
            or "mining" in details["result"].lower()
        ):
            sum[16] = sum[16] + 1
        elif details["result"] and (
            details["result"].lower().find("pup") >= 0
            or "potentially unwanted program" in details["result"].lower()
        ):
            sum[17] = sum[17] + 1
        elif details["result"] and (
            details["result"].lower().find("c2") >= 0
            or "command and control" in details["result"].lower()
        ):
            sum[18] = sum[18] + 1
        elif details["result"] and details["result"].lower().find("riskware") >= 0:
            sum[19] = sum[19] + 1
        elif details["result"] and details["result"].lower().find("spam") >= 0:
            sum[20] = sum[20] + 1
        elif (
            details["result"]
            and details["result"].lower().find("drive-by download") >= 0
        ):
            sum[21] = sum[21] + 1
        elif (
            details["result"]
            and details["result"].lower().find("rat") >= 0
            and not ("unrated" in details["result"].lower())
        ):
            sum[22] = sum[22] + 1
        elif details["result"] and details["result"].lower().find("malware") >= 0:
            sum[23] = sum[23] + 1
        elif details["result"] and (
            details["result"].lower().find("malicious") >= 0
            or details["result"].lower().find("threat") >= 0
            or details["result"].lower().find("suspicious") >= 0
            or details["result"].lower().find("unwanted") >= 0
        ):
            sum[24] = sum[24] + 1
    max_i = 0
    for i in range(1, 23):
        if sum[max_i] < sum[i]:
            max_i = i
    if sum[max_i] == 0:
        if sum[24] > 0:
            max_i = 24
        else:
            max_i = 25
    behavior_info = interpret_behavior(malware_type[max_i])
    return behavior_info

def format_vt_report(data, target_type, target):
    """VirusTotal API v3のレスポンスを、アプリ向けの統一形式に整形する"""
    try:
        attributes = data.get("data", {}).get("attributes", {})
        if not attributes:
            return {"success": False, "error": "有効なデータが見つかりません", "data": None}

        stats = attributes.get("last_analysis_stats", {})
        reputation = attributes.get("reputation")
        rating = calculate_custom_VTrating(stats, reputation)
        
        last_analysis_date = attributes.get("last_analysis_date")
        date_str = datetime.fromtimestamp(last_analysis_date).strftime('%Y-%m-%d %H:%M:%S')if last_analysis_date else "不明"
        
        last_analysis_results = attributes.get("last_analysis_results", {})
        category = interpret_results(last_analysis_results)
        
        details_list = []
        for vendor_name, result_data in last_analysis_results.items():
            details_list.append({
                "vendor": vendor_name,
                "category": translate_result(result_data.get("category")),
                "result": result_data.get("result", "N/A")
            })

        return {
            "success": True, "error": None,
            "data": {
                "target": target, "type": target_type,
                "summary": {
                    "rating": rating,
                    "positives": stats.get("malicious", 0) + stats.get("suspicious", 0),
                    "total": sum(stats.values())
                },
                "attributes": {
                    "最終分析日時": date_str, 
                    "悪意あり": stats.get("malicious", 0),
                    "疑わしい": stats.get("suspicious", 0), 
                    "安全": stats.get("harmless", 0),
                    "未検出": stats.get("undetected", 0)
                },
                "details": details_list,
                "category": category
            }
        }
    except Exception as e:
        return {"success": False, "error": f"レスポンスの解析エラー: {str(e)}", "data": None}
    
def format_urlscan_report(urlscan_data, target_url):
    
    #Urlscanのレポートを整形する。

    if not urlscan_data or urlscan_data.get("status") in ["API_LimitOver", "Unmanageable_Scan_URL"]:
        status = urlscan_data.get("status") if urlscan_data else "Error"

        if status in ["API_LimitOver", "Unmanageable_Scan_URL"]:
            custom_rating = f"⚪️ 判定不可({status})"
        else:
            # urlscan_dataがNoneだった場合など
            custom_rating = "⚪️ 判定不可"

        return {
            "target": target_url,
            "status": status,
            "task": None,
            "uuid": None,
            "verdicts": None,
            "custom_rating":  custom_rating,
            "security_state_summary": {
                "secure": 0,
                "insecure": 0,
                "unknown": 0,
                "total": 0
            }
        }

    # 通常のUrlscanレポートデータがある場合
    result = {
        "target": target_url,
        "status": "completed",  
        "task": urlscan_data.get("task"),
        "uuid": urlscan_data.get("uuid"),
        "verdicts": urlscan_data.get("verdicts"),
    }
    
    rating_data = calculate_custom_URLrating(urlscan_data)
    result["custom_rating"] = rating_data.get("rating")
    result["security_state_summary"] = rating_data.get("security_state_summary")
    
    return result

# --- 各種スキャンを実行する関数群 ---

# URLエンコード
def encode_url_id(url: str) -> str:
    """base64url エンコード（末尾の "=" は削除）"""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

# VirusTotal
def get_virustotal_report(api_key: str, url: str) -> dict:
    """VirusTotal で既存の URL レポートを取得"""
    url_id = encode_url_id(url)
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key.strip()}

    resp = requests.get(vt_url, headers=headers)
    if resp.status_code == 404:
        return {"success": True, "data": None, "error": "not_found"}
    resp.raise_for_status()
    return resp.json()

def submit_virustotal_scan(api_key: str, url: str) -> str:
    """VirusTotal に URL を提出して分析IDを取得"""
    
    if not url or not url.strip():
        raise ValueError("URLが空です")

    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key.strip()}
    payload = {"url": url.strip()}

    #resp = requests.post(vt_url, json=payload, headers=headers)
    resp = requests.post(vt_url, data=payload, headers=headers) #VirusTotalはdataパラメータで送信するフォーム形式 (application/x-www-form-urlencoded) を要求します。
    resp.raise_for_status()

    analysis_id = resp.json().get("data", {}).get("id")
    if not analysis_id:
        raise Exception("VirusTotal: 分析IDを取得できませんでした。")
    return analysis_id

def poll_virustotal_result(api_key: str, analysis_id: str, interval=5, timeout=120) -> dict:
    """分析完了までポーリングして結果を返す"""
    start = time.time()
    while time.time() - start < timeout:
        resp = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                            headers={"x-apikey": api_key.strip()})
        resp.raise_for_status()
        data = resp.json()
        # data が None の場合はリトライ
        if data.get("data") is None:
            current_app.logger.debug(f"VT API returned no data yet for {analysis_id}, retrying...")
            time.sleep(interval)
            continue
        status = data.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            # 完了直後はデータが揃っていない場合があるので少し待つ
            time.sleep(10)
            return "completed"
        time.sleep(interval)
    return None

# Urlscan
def submit_urlscan_scan(api_key: str, url: str) -> str:
    #Urlscan に URL を提出して新規スキャン

    headers = {"Content-Type": "application/json", "API-Key": api_key.strip()}
    
    resp = requests.post("https://urlscan.io/api/v1/scan/", json={"url": url.strip()}, headers=headers)
    if resp.status_code == 429:
        # レートリミット超過
        return "API_LimitOver"
    
    if resp.status_code == 400:
        #対応していないURL
        return "Unmanageable_Scan_URL"

    resp.raise_for_status()
    return resp.json().get("uuid")
    
def poll_urlscan_result(uuid: str, interval=5, timeout=120) -> dict:
    
    if uuid == "API_LimitOver":
        return "API_LimitOver"
    elif uuid == "Unmanageable_Scan_URL":
        return "Unmanageable_Scan_URL"
    start = time.time()
    while time.time() - start < timeout:
        try:
            resp = requests.get(f"https://urlscan.io/api/v1/result/{uuid}/")
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 429:
                # 途中で上限超過になるケース (なさそうだけど)
                return "Error"
        except requests.RequestException as e:
            print(f"[Urlscan] Polling error: {e}")
            break
        time.sleep(interval)
    return None

# 統合
def get_or_rescan_url(api_key_vt: str, api_key_scan: str, url: str) -> dict:
    """
    URL を VirusTotal と Urlscan に送信して結果を取得
    - VirusTotal: 既存レポートが半年以内なら取得、古いor未登録なら再スキャン（ポーリング）
    - Urlscan: 常に新規スキャン（ただしAPI上限時,対応していないURLは 'Error' を返す）
    """
    if not url or not url.strip():
        raise ValueError("URLが空です")

    result = {"success": True, "data": {"virustotal": None, "urlscan": None}}
    flag = 0

    # --- VirusTotal ---
    vt_report = get_virustotal_report(api_key_vt, url)
    if vt_report.get("data"):
        last_date = vt_report["data"].get("attributes", {}).get("last_analysis_date")
        if last_date and (datetime.utcnow() - datetime.fromtimestamp(last_date)) < timedelta(days=MAX_AGE_DAYS):
            result["data"]["virustotal"] = vt_report
            status = "completed0"
            flag = 1
        else:
            analysis_id = submit_virustotal_scan(api_key_vt, url)
            status = poll_virustotal_result(api_key_vt, analysis_id)
        if status == "completed" and flag ==0:
            # 完了したら改めてレポートを取得
            result["data"]["virustotal"] = get_virustotal_report(api_key_vt, url)
    else: #data None = 新規の場合
        analysis_id = submit_virustotal_scan(api_key_vt, url)
        status = poll_virustotal_result(api_key_vt, analysis_id)
        if status == "completed":
            # 完了したら改めてレポートを取得
            result["data"]["virustotal"] = get_virustotal_report(api_key_vt, url)

    # --- Urlscan ---
    uuid = submit_urlscan_scan(api_key_scan, url)
    urlscan_result = poll_urlscan_result(uuid)
    
    if urlscan_result == "API_LimitOver":
        result["data"]["urlscan"] = {"status": "API_LimitOver"}
    elif urlscan_result == "Unmanageable_Scan_URL":
        result["data"]["urlscan"] = {"status": "Unmanageable_Scan_URL"}
    else:
        result["data"]["urlscan"] = urlscan_result

    return result

def format_url_report(vt_data, urlscan_data, target_url):
    """
    VirusTotal と Urlscan の統合レポートをアプリ用形式に整形
    """
    result = {
        "success": True,
        "target": target_url,
        "virustotal": None,
        "urlscan": None
    }

    # VirusTotal データがある場合
    if vt_data:
        result["virustotal"] = format_vt_report(vt_data, "URL", target_url)

    # Urlscan データがある場合
    if urlscan_data:
        result["urlscan"] = format_urlscan_report(urlscan_data, target_url)

    return result

#URL以外

def get_ip_report(api_key, ip_to_scan):
    """IPアドレスのレポートを取得する"""
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_to_scan}"
    headers = {"x-apikey": api_key}
    response = requests.get(vt_url, headers=headers)

    if response.status_code == 404:
        return {"success": True, "data": None, "error": "not_found"}
    
    response.raise_for_status()
    return format_vt_report(response.json(), "IPアドレス", ip_to_scan)

def get_hash_report(api_key, hash_to_scan):
    """ファイルハッシュのレポートを取得する"""
    vt_url = f"https://www.virustotal.com/api/v3/files/{hash_to_scan}"
    headers = {"x-apikey": api_key}
    response = requests.get(vt_url, headers=headers)

    if response.status_code == 404:
        return {"success": True, "data": None, "error": "not_found"}

    response.raise_for_status()
    return format_vt_report(response.json(), "ファイルハッシュ", hash_to_scan)

def upload_file_for_scan(api_key, file_object):
    """ファイルをアップロードしてスキャンを行い、結果を返す"""
    vt_url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": api_key}
    file_object.seek(0)
    files = {"file": (file_object.filename, file_object, file_object.mimetype)}

    # --- アップロード ---
    response = requests.post(vt_url, headers=headers, files=files)
    response.raise_for_status()
    #print("Upload response:", response.json())

    print("Upload response:", response.json(), file=sys.stderr)

    analysis_id = response.json().get("data", {}).get("id")

    if not analysis_id:
        raise Exception("APIレスポンスから分析IDを取得できませんでした。")

    # --- ポーリングして分析完了を待つ ---
    status = poll_virustotal_result(api_key, analysis_id)
    if status == "completed":
        # ファイルのハッシュを計算して、ハッシュでレポートを取得
        file_object.seek(0)
        sha256_hash = hashlib.sha256(file_object.read()).hexdigest()
        analysis_data = get_hash_report(api_key, sha256_hash)
    else:
        return {
            "success": False,
            "data": None,
            "status": "queued",
            "error": "pending"
        }

    return analysis_data

#使って無い説
def get_analysis_result(api_key, analysis_id):
    """分析IDを使い、VirusTotalから分析の進捗や結果を取得する"""
    vt_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": api_key}
    response = requests.get(vt_url, headers=headers)
    response.raise_for_status()
    
    result_data = response.json()
    status = result_data.get("data", {}).get("attributes", {}).get("status")

    # まだ分析中
    if status in ["queued", "in-progress"]:
        return {
            "success": True,
            "data": None,
            "status": status,
            "error": "pending"
        }

    # 分析完了だが meta.url_info がない
    if status == "completed":
        url_report_data = result_data.get("meta", {}).get("url_info")
        if not url_report_data:
            return {
                "success": True,
                "data": None,
                "status": "completed",
                "error": "report_not_ready"
            }

        # レポートがある場合は整形
        target_url = (
            url_report_data.get("data", {})
            .get("attributes", {})
            .get("url", "N/A")
        )
        formatted = format_vt_report(url_report_data, "URL", target_url)
        return {
            "success": True,
            "status": "completed",
            "data": formatted
        }

    # 想定外のステータス
    return {
        "success": False,
        "data": None,
        "status": status,
        "error": "unknown_status"
    }