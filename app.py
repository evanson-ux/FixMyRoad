from flask import Flask, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_mail import Mail
from config import Config
import os

db = SQLAlchemy()
jwt = JWTManager()
migrate = Migrate()
mail = Mail()

def create_app():
    app = Flask(__name__, static_folder="../client/build", static_url_path="/")
    app.config.from_object(Config)

    # ✅ Flask-Mail Configuration
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False
    app.config['MAIL_USERNAME'] = 'evansontonkei66@gmail.com'   # replace with env var in prod
    app.config['MAIL_PASSWORD'] = 'evanson123'                  # replace with env var in prod
    app.config['MAIL_DEFAULT_SENDER'] = 'evansontonkei66@gmail.com'

    db.init_app(app)
    jwt.init_app(app)
    CORS(app)
    migrate.init_app(app, db)
    mail.init_app(app)

    from routes import main as main_blueprint
    app.register_blueprint(main_blueprint)

    # ✅ Import models so Alembic sees them
    from models.User import User
    from models.Report import Report

    # ✅ Serve React frontend
    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def serve_react(path):
        if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
            return send_from_directory(app.static_folder, path)
        return send_from_directory(app.static_folder, "index.html")

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
