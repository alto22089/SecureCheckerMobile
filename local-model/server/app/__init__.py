# app/__init__.py

from flask import Flask
from config import Config
from .extensions import db

def create_app(config_class=Config):
    # Flaskアプリケーションのインスタンスを作成
    app = Flask(__name__)
    
    # config.pyから設定を読み込む
    app.config.from_object(config_class)

     # dbをアプリケーションに紐付け
    db.init_app(app)

    # アプリケーションに、apiブループリントを登録する
    # これにより、app/api/routes.pyで定義したURLが有効になる
    from .api import bp as api_bp
    app.register_blueprint(api_bp)

    # ここに、もし将来的に別の機能ブループリント（例：ユーザー管理）を追加した場合、
    # 同様に登録していく
    # from .auth import bp as auth_bp
    # app.register_blueprint(auth_bp)

    # 設定済みのアプリケーションインスタンスを返す
    return app