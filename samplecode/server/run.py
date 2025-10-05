from app import create_app

# app/__init__.py の create_app() 関数を呼び出して、アプリ本体を生成する
app = create_app()

if __name__ == '__main__':
    # このファイルが直接 `python run.py` として実行された場合にのみ、
    # 開発用の簡易サーバーを起動する。
    # (Docker/Gunicornから起動される環境では、使われない)
    app.run(debug=True, host='0.0.0.0', port=5000)