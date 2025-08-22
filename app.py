from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_mail import Mail   # ✅ Add this
from config import Config

db = SQLAlchemy()
jwt = JWTManager()
migrate = Migrate()
mail = Mail()   # ✅ Initialize Mail

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # ✅ Flask-Mail Configuration
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'      # change if using another provider
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False
    app.config['MAIL_USERNAME'] = 'evansontonkei66@gmail.com'       # your email
    app.config['MAIL_PASSWORD'] = 'evanson123'        # app password
    app.config['MAIL_DEFAULT_SENDER'] = 'evansontonkei66@gmail.com'

    db.init_app(app)
    jwt.init_app(app)
    CORS(app)
    migrate.init_app(app, db)
    mail.init_app(app)   # ✅ Initialize Mail with app

    from routes import main as main_blueprint
    app.register_blueprint(main_blueprint)

    # ✅ Import models so Alembic sees them
    from models.User import User
    from models.Report import Report

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
