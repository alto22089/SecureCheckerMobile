from app import db
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from .extensions import db

class User(db.Model):
    #ユーザー情報モデル
    id = db.Column(db.Integer, primary_key=True)  # ユーザーID（自動採番）
    username = db.Column(db.String(64), unique=True, nullable=False)  # ユーザー名（ユニーク・必須）
    password_hash = db.Column(db.String(256))  # パスワードのハッシュ
    scans = db.relationship('ScanHistory', backref='author', lazy='dynamic')  
    # ユーザーが作成したスキャン履歴のリスト。ScanHistory.authorで逆参照可能

    def set_password(self, password):
        #パスワードをハッシュ化して保存　PBKDF2使用
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha512:600000', salt_length=16)

    def check_password(self, password):
        #入力されたパスワードとハッシュを照合
        return check_password_hash(self.password_hash, password)

class ScanHistory(db.Model):
    #スキャン履歴モデル
    
    id = db.Column(db.Integer, primary_key=True)  # 履歴ID（自動採番）
    scan_type = db.Column(db.String(64), nullable=False)  # スキャンのジャンル（例: "URL", "File"）
    scan_target = db.Column(db.LargeBinary, nullable=False)  # スキャン対象（URLやファイルハッシュ）
    result_rating = db.Column(db.String(128), nullable=False) #スキャン結果(評価のみ)
    timestamp = db.Column(
        db.DateTime, 
        default=lambda: datetime.now(timezone.utc), 
        index=True
    )  
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  
   
class Feedback(db.Model):
    #ユーザーフィードバックモデル
    id = db.Column(db.Integer, primary_key=True)  # フィードバックID（自動採番）
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    #フィードバックを提供したユーザーのID
    content = db.Column(db.Text, nullable=False)  # フィードバック内容
    timestamp = db.Column(
        db.DateTime, 
        default=lambda: datetime.now(timezone.utc), 
        index=True
    )

