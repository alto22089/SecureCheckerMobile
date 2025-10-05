# app/api/__init__.py

from flask import Blueprint

# (1) ブループリントの作成
#    「'api'」という名前のブループリント（専門フロアの設計図）を作成します。
#    このフロアに属するすべてのURLの先頭には、自動的に「/api」が付きます。
bp = Blueprint('api', __name__, url_prefix='/api')

# (2) ルート（URL定義）のインポート
#    （循環インポートを避けるため、最後に記述するのが一般的）
from . import routes