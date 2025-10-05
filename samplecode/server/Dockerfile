# Dockerfile
# ベースイメージとして、軽量なPython 3.9環境を選択
FROM python:3.9

# コンテナ内の作業ディレクトリを /app に設定
WORKDIR /app

#requirements.txt だけをコピーし、ライブラリをインストール
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# アプリケーションのコード全体をコピー
COPY . .

# Gunicornが5000番ポートでリクエストを待ち受けることを示す
EXPOSE 5000

# entrypoint.shに実行権限を付与
RUN chmod +x ./entrypoint.sh

# コンテナ起動時にentrypoint.shを実行する
ENTRYPOINT ["./entrypoint.sh"]
