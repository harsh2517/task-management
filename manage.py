from app import app, db
from flask_migrate import Migrate, MigrateCommand
from flask.cli import FlaskGroup

migrate = Migrate(app, db)
cli = FlaskGroup(app)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

with app.app_context():
    db.create_all()

