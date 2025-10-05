import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))

# .envファイルから環境変数を読み込む
load_dotenv()

class Config:
    """アプリケーションの設定を保持"""
    VT_API_KEY = os.environ.get("VT_API_KEY")
    URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY")
    APP_SECRET_TOKEN = os.environ.get("APP_SECRET_TOKEN")
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'data/app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False