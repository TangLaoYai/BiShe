"""Flask 应用入口：智能合约漏洞审计系统后端

启动：python app.py   （默认 http://127.0.0.1:5000）
生产环境构建后的前端由本服务直接托管（frontend/dist）。
"""
import os

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS

import config
import database
from api import register_blueprints


def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)
    app.secret_key = config.SECRET_KEY
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH
    app.config["PERMANENT_SESSION_LIFETIME"] = 60 * 60 * 24 * 7  # 7天

    CORS(app, supports_credentials=True, origins=config.CORS_ORIGINS)

    config.ensure_dirs()
    database.init_db()
    register_blueprints(app)

    @app.teardown_appcontext
    def _cleanup(exc):
        if database.Session is not None:
            database.Session.remove()

    @app.errorhandler(404)
    def _not_found(e):
        return jsonify({"message": "接口不存在"}), 404

    @app.errorhandler(500)
    def _server_error(e):
        return jsonify({"message": "服务器内部错误"}), 500

    _register_spa(app)
    return app


def _register_spa(app: Flask):
    """托管 Vue3 构建产物 frontend/dist（存在时）；路由不存在时回退 index.html"""
    dist = os.path.join(config.BASE_DIR, "frontend", "dist")
    if not os.path.isdir(dist):
        @app.get("/")
        def _no_frontend():
            return jsonify({"message": "前端未构建：请先执行 frontend 下的 npm run build，"
                                       "或使用 npm run dev 启动前端开发服务器"})
        return

    @app.get("/")
    def _index():
        return send_from_directory(dist, "index.html")

    @app.get("/<path:path>")
    def _spa(path):
        full = os.path.join(dist, path)
        if os.path.isfile(full):
            return send_from_directory(dist, path)
        return send_from_directory(dist, "index.html")


app = create_app()

if __name__ == "__main__":
    app.run(host=config.HOST, port=config.PORT, debug=False, threaded=True)
