from flask import request, jsonify, current_app
from . import bp
from . import analysis
from ..auth import token_required
import requests
from urllib.parse import quote, urlparse, urlunparse
import jwt
from datetime import datetime, timezone, timedelta
from app import db
from app.models import User, ScanHistory, Feedback 
#import time
from cryptography.fernet import Fernet

def encrypt_data(data_string: str) -> bytes:
 
    if not data_string:
        return None

    key = current_app.config['ENCRYPTION_KEY'].encode()  
    f = Fernet(key)

    return f.encrypt(data_string.encode('utf-8'))


def decrypt_data(encrypted_bytes: bytes) -> str:
   
    if not encrypted_bytes:
        return None

    key = current_app.config['ENCRYPTION_KEY'].encode()
    f = Fernet(key)

    return f.decrypt(encrypted_bytes).decode('utf-8')

# --- ユーザー管理 ---
#ユーザ登録
@bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "ユーザー名とパスワードが必要です"}), 400
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"error": "このユーザー名は既に使用されています"}), 400
    
    user = User(username=data['username'])
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "ユーザーが正常に登録されました"}), 201

#ログイン
@bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"message": "ログインできません"}), 401
    
    user = User.query.filter_by(username=data['username']).first()
    if user is None or not user.check_password(data['password']):
        return jsonify({"message": "ログインできません"}), 401
        
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.now(timezone.utc) + timedelta(minutes=30)
    }, current_app.config['JWT_SECRET_KEY'], algorithm="HS256")
    
    return jsonify({'token': token})

#旧Ver

def normalize_url(url: str) -> str:
    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = quote(parsed.path, safe="/")
    return urlunparse((scheme, netloc, path, "", "", ""))

# --- URLスキャン ---
@bp.route('/scan/url', methods=['POST'])
@token_required
def scan_url(current_user): 
    target_url = request.json.get("url")
    #target_url = normalize_url(target_url)

    if not target_url or not target_url.strip():
        return jsonify({"success": False, "error": "スキャン対象のURLが指定されていません。"}), 400
    
    target_url = target_url.strip()
    vt_api_key = current_app.config["VT_API_KEY"]
    urlscan_api_key = current_app.config["URLSCAN_API_KEY"]

    try:
        # サーバー側で新規/再スキャン → ポーリングして結果取得
        result = analysis.get_or_rescan_url(vt_api_key, urlscan_api_key, target_url)

        if not result["data"]["virustotal"] or not result["data"]["urlscan"]:
            return jsonify({
                "success": False,
                "error": "スキャン結果の取得に失敗しました",
                "data": result["data"]
            }), 500

        # analysis.pyで結果を整形
        formatted_report = analysis.format_url_report(
            result["data"]["virustotal"],
            result["data"]["urlscan"],
            target_url
        )

        # DB登録の処理
        vt_rating = formatted_report.get("virustotal", {}).get("data", {}).get("summary", {}).get("rating", "N/A")
        urlscan_rating = formatted_report.get("urlscan", {}).get("custom_rating", "N/A")

        final_rating = f"VirusTotal：{vt_rating} - URLScanio:{urlscan_rating}"

        # ScanHistoryテーブルに書き込むための、新しい行オブジェクトを作成
        new_history = ScanHistory(
            scan_target=encrypt_data(target_url),
            scan_type="URL",
            result_rating=final_rating, # ratingだけをfinal_rating列に保存
            author=current_user      # このスキャンを実行したユーザーと紐づける
        )
        db.session.add(new_history) # 新しい行をデータベースセッションに追加
        db.session.commit()         # 変更をデータベースに確定（書き込み）

        # クライアントには、整形されたレポート全体を返す
        return jsonify(formatted_report)

    except requests.exceptions.HTTPError as e:
        current_app.logger.error(
            f"APIリクエスト失敗: {e.response.status_code} {e.request.url} - {e.response.text}"
        )
        return jsonify({"success": False, "error": "外部APIとの連携中にエラーが発生しました。"}), 502

    except Exception as e:
        current_app.logger.error(f"予期せぬエラー: {str(e)}")
        return jsonify({"success": False, "error": "サーバー内部で予期せぬエラーが発生しました。"}), 500
    
# --- IPスキャン ---
@bp.route('/scan/ip', methods=['POST'])
@token_required
def scan_ip():
    data = request.get_json()
    if not data or 'ip' not in data:
        return jsonify({"error": "IPアドレスが指定されていません"}), 400
    try:
        # IPレポート取得（サーバー側ポーリングを含む）
        result = analysis.get_ip_report(current_app.config['VT_API_KEY'], data['ip'])
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": f"サーバーエラー: {str(e)}"}), 500


# --- ハッシュスキャン ---
@bp.route('/scan/hash', methods=['POST'])
@token_required
def scan_hash():
    data = request.get_json()
    if not data or 'hash' not in data:
        return jsonify({"error": "ハッシュ値が指定されていません"}), 400
    try:
        # ハッシュレポート取得（サーバー側ポーリングを含む）
        result = analysis.get_hash_report(current_app.config['VT_API_KEY'], data['hash'])
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": f"サーバーエラー: {str(e)}"}), 500

# --- ファイル事前チェック（ハッシュ確認のみ） ---
@bp.route('/scan/file/check', methods=['POST'])
@token_required
def scan_file_check(current_user):
    data = request.get_json()
    if not data or 'hash' not in data:
        return jsonify({"error": "hashが指定されていません"}), 400

    file_hash = data['hash']
    try:
        result = analysis.get_hash_report(current_app.config['VT_API_KEY'], file_hash)
        if result.get("data"):
            # 既存レポートがある場合
            #return jsonify({"success": True, "data": result["data"], "error": None})
            # analysis.pyで結果を整形

            # DB登録の処理
            final_rating = result.get("data", {}).get("summary", {}).get("rating", "N/A")

            # ScanHistoryテーブルに書き込むための、新しい行オブジェクトを作成
            new_history = ScanHistory(
                scan_target=encrypt_data(file_hash),
                scan_type="File_hash",
                result_rating= final_rating, # ratingだけをfinal_rating列に保存
                author= current_user      # このスキャンを実行したユーザーと紐づける
            )
            db.session.add(new_history) # 新しい行をデータベースセッションに追加
            db.session.commit()         # 変更をデータベースに確定（書き込み）

            # クライアントには、整形されたレポート全体を返す
            return jsonify({"success": True, "data": result["data"], "error": None})
        else:
            # 未登録の場合、クライアントに確認させる
            return jsonify({
                "success": True,
                "data": None,
                "error": "not_found",
                "hash": file_hash,
                "message": "このファイルは未登録です。アップロードしてスキャンしますか？"
            })
    except Exception as e:
        return jsonify({"success": False, "error": f"サーバーエラー: {str(e)}", "data": None}), 500

# --- ファイルアップロード後のスキャン ---
@bp.route('/scan/file/upload', methods=['POST'])
@token_required
def scan_file_upload(current_user):
    if 'file' not in request.files:
        return jsonify({"error": "ファイルがありません"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "ファイルが選択されていません"}), 400
    try:
        upload_result = analysis.upload_file_for_scan(current_app.config['VT_API_KEY'], file)

        # DB登録の処理
        final_rating = upload_result.get("data", {}).get("summary", {}).get("rating", "N/A")
        file_name = upload_result.get("data", {}).get("target", "N/A")
        # ScanHistoryテーブルに書き込むための、新しい行オブジェクトを作成
        new_history = ScanHistory(
            scan_target=encrypt_data(file_name),
            scan_type="File_upload",
            result_rating= final_rating, # ratingだけをfinal_rating列に保存
            author= current_user      # このスキャンを実行したユーザーと紐づける
        )
        db.session.add(new_history) # 新しい行をデータベースセッションに追加
        db.session.commit()         # 変更をデータベースに確定（書き込み）

        return jsonify(upload_result)
    except Exception as e:
        return jsonify({"success": False, "error": f"サーバーエラー: {str(e)}", "data": None}), 500


# --- 分析結果の取得（ポーリング用） ---
@bp.route('/result/<analysis_id>', methods=['GET'])
@token_required
def get_result(analysis_id):
    try:
        result = analysis.get_analysis_result(current_app.config['VT_API_KEY'], analysis_id)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": f"サーバーエラー: {str(e)}", "data": None}), 500

@bp.route('/feedback', methods=['POST'])
@token_required
def feedback(current_user):
    try:
        # JSONリクエストを取得
        data = request.get_json()
        if not data or 'content' not in data:
            return jsonify({"error": "フィードバック内容がありません"}), 400

        content = data['content'].strip()
        if content == "":
            return jsonify({"error": "フィードバック内容が空です"}), 400

        # Feedbackレコード作成
        new_feedback = Feedback(
            user_id=current_user.id,  
            content=content
        )

        db.session.add(new_feedback)
        db.session.commit()

        return jsonify({
            "success": True,
            "message": "フィードバックを保存しました",
            "feedback_id": new_feedback.id
        }), 201

    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"サーバーエラー: {str(e)}"
        }), 500