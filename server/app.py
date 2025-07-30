from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate  # ✅ NEW
from config import Config

db = SQLAlchemy()
jwt = JWTManager()
migrate = Migrate()  # ✅ NEW

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    jwt.init_app(app)
    CORS(app)
    migrate.init_app(app, db)  # ✅ NEW

    from routes import main as main_blueprint
    app.register_blueprint(main_blueprint)

    # ✅ Import models before creating tables
    from models.User import User
    from models.Report import Report

    with app.app_context():
        db.create_all()

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
