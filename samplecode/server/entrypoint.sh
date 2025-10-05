#!/bin/sh
set -e

# データベースの初期化スクリプトを実行
echo "Initializing the database..."
python init_db.py

# Webサーバーを起動する
echo "Starting the Gunicorn server..."
exec gunicorn --workers 4 --bind 0.0.0.0:5000 --log-file - --log-level debug --timeout 150 "run:app"