from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os
from datetime import timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()

def create_app():
    app = Flask(__name__, template_folder='templates')
    app.secret_key = os.urandom(24)
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

    # Inicjalizacja Flask-Limiter
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"]
    )
    
    db.init_app(app)
    limiter.init_app(app)

    app.limiter = limiter

    from . import routes
    app.register_blueprint(routes.bp)

    with app.app_context():
        db.create_all()

    return app