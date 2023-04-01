import os
from flask import Flask, render_template, request, flash, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
import pandas as pd
from csv import DictReader
from sqlalchemy.orm import Session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, RadioField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.from_object(__name__)
db_path = os.path.join(os.path.dirname(__file__), 'recipes.db')
db_uri = 'sqlite:///{}'.format(db_path)

app.config['SECRET_KEY'] = 'DzV0uepzTJMe6rp6SA3XSJHjXOmUSmGG'
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Recipe table


class Recipe(db.Model):
    key = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    instructions = db.Column(db.String(1000), nullable=False)
    cuisine = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(200), nullable=False)
    ingredients = db.Column(db.String(1000), nullable=False)
    time = db.Column(db.String(20), nullable=False)
    servings = db.Column(db.Integer, nullable=False)
    diet = db.Column(db.String(20), nullable=False)

    def __repr__(self):
        return f"Recipe('{self.name}', '{self.cuisine}', '{self.time}', '{self.diet}', '{self.ingredients}', '{self.instructions}', '{self.image}')"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
"""
class Cooked(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('User.id'))
    recipe_id = db.Column(db.Integer, db.ForeignKey('Recipe.key'))
    user = db.relationship('User', backref=db.backref('Cooked', lazy=True))
    recipe = db.relationship('Recipe', backref=db.backref('Cooked', lazy=True))

    def __repr__(self):
        return f"Cooked('{self.user_id}', '{self.recipe_id}')"
"""
db.create_all()


def populate_database(session: Session):
    with open('Recipe.csv', 'r') as f:
        reader = DictReader(f)
        for row in reader:
            recipe = Recipe(
                name=row['Recipe Name'],
                instructions=row['Instruction'],
                cuisine=row['Cuisine'],
                image=row['Image'],
                ingredients=row['Ingredients'],
                time=int(row['Time'].replace('minutes', '')),
                servings=int(row['Servings']),
                diet=row['Diet']
            )
            db.session.add(recipe)

    db.session.commit()

# Define the homepage route
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=15)], render_kw={"placeholder": "Username"})
    password = PasswordField("Password", validators=[InputRequired(), Length(
        min=4, max=50)], render_kw={"placeholder": "Password"})
    remember = BooleanField('Remember me')


class RegisterForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(
        message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email Address"})
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=15)], render_kw={"placeholder": "Username"})
    password = PasswordField("Password", validators=[InputRequired(), Length(
        min=4, max=50)], render_kw={"placeholder": "Password"})


@app.route('/', methods=['GET', 'POST'])
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(
            form.password.data, method='sha256')
        new_user = User(username=form.username.data,
                        email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account is successfully created! Please login to get recipe recommendation! :)')
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                flash('Login successful!')
                return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))


@app.route('/homepage', methods=['GET', 'POST'])
def homepage():
    # query recipes for Mexican cuisine, Keto diet, and Air Fryer Recipes
    mexican_recipes = Recipe.query.filter_by(cuisine='Mexican').limit(9).all()
    italian_recipes = Recipe.query.filter_by(cuisine='Italian').limit(9).all()
    american_recipes = Recipe.query.filter_by(cuisine='American').limit(9).all()
    # render homepage with recipe sections
    return render_template('homepage.html',
                           mexican_recipes=mexican_recipes,
                           american_recipes=american_recipes, italian_recipes=italian_recipes)


@app.route('/search', methods=['GET', 'POST'])
def index():
  return render_template('index.html')


@app.route('/search_bar', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        search_term = request.form['search_term']
        results = Recipe.query.filter(
            Recipe.name.like(f'%{search_term}%'),
            Recipe.ingredients.like(f'%{search_term}%'),
            Recipe.cuisine.like(f'%{search_term}%'),
            Recipe.diet.like(f'%{search_term}%'),
            Recipe.instructions.like(f'%{search_term}%')
        ).all()
        return render_template('search.html', results=results, search_term=search_term)
    return redirect(url_for('index'))


# Define the recommendation route
@app.route('/recommendation', methods=['POST'])
@login_required
def recommendation():
    ingredients = [x.strip() for x in request.form['ingredients'].split(',')]
    cuisine = request.form['cuisine']
    time = request.form['time']
    diet = request.form['diet']
    
    # Query the database to get the matching recipes
    recipes = Recipe.query.filter(
        Recipe.cuisine.contains(cuisine), Recipe.diet.contains(diet), Recipe.time <= time).all()
    matched_recipes = []
    
    for recipe in recipes:
        if all(ingredient.lower() in recipe.ingredients for ingredient in ingredients):
            matched_recipes.append(recipe)

    return render_template('recommendation.html', recipes=matched_recipes)


@app.route('/recipe/<int:recipe_id>')
def recipe_detail(recipe_id):
    recipe = Recipe.query.get(recipe_id)
    return render_template('recipe_detail.html', recipe=recipe)

if __name__ == '__main__':
    #populate_database(db.session)
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
