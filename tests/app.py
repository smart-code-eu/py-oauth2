from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://finance_app:finance_app@localhost:5432/finance_app'#'sqlite:////Users/darian/Desktop/test2.db'
db = SQLAlchemy(app)