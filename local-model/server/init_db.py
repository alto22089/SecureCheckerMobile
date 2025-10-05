import time
from sqlalchemy.exc import OperationalError
from app import create_app, db

# Flaskアプリケーションのインスタンスを作成
app = create_app()

# アプリケーションコンテキスト内でデータベース操作を実行
with app.app_context():
    # データベースが起動するまで少し待つ処理（おまけ）
    retries = 5
    while retries > 0:
        try:
            print("✅ データベースの初期化を試みます...")
            # 存在しないテーブルのみを作成
            db.create_all()
            print("✅ データベースの初期化に成功しました。")
            break
        except OperationalError:
            retries -= 1
            print("❌ DB接続に失敗。5秒後に再試行します...")
            time.sleep(5)
        except Exception as e:
            print(f"❌ データベースの初期化中に予期せぬエラーが発生しました: {e}")
            # エラーがあった場合はスクリプトを異常終了させる
            exit(1)