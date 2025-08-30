from flask import Flask, request, jsonify, render_template, redirect, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity, set_access_cookies, unset_jwt_cookies
import os

# Define base directory for relative paths
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__,
            template_folder=os.path.join(BASE_DIR, 'templates'),
            static_folder=os.path.join(BASE_DIR, 'static'))

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Change this in production
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key_here' # Change this in production

# JWT Configuration
app.config['JWT_TOKEN_LOCATION'] = ['cookies'] # Only look for tokens in cookies
app.config['JWT_COOKIE_SECURE'] = False # Set to True in production with HTTPS
app.config['JWT_COOKIE_CSRF_PROTECT'] = False # Disable CSRF protection for simplicity in development

db = SQLAlchemy(app)
jwt = JWTManager(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)
    imageUrl = db.Column(db.String(200), nullable=True)

class SocialLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    platform = db.Column(db.String(50), nullable=False)
    url = db.Column(db.String(200), nullable=False)

# Create database and default admin user
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin')
        admin_user.set_password('adminpass')
        db.session.add(admin_user)
        db.session.commit()
        print('Default admin user created: username="admin", password="adminpass"')

# API Endpoints

# User Authentication
@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        access_token = create_access_token(identity=user.id)
        response = jsonify(message='Login successful')
        set_access_cookies(response, access_token)
        return response, 200
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    response = jsonify({'message': 'Logged out successfully'})
    unset_jwt_cookies(response)
    return response, 200

@app.route('/api/status', methods=['GET'])
@jwt_required(optional=True)
def status():
    current_user_id = get_jwt_identity()
    if current_user_id:
        return jsonify(logged_in=True, user_id=current_user_id), 200
    return jsonify(logged_in=False), 200

# Product Management
@app.route('/api/products', methods=['GET'])
def get_products():
    products = Product.query.all()
    return jsonify([{'id': p.id, 'name': p.name, 'category': p.category, 'price': p.price, 'description': p.description, 'imageUrl': p.imageUrl} for p in products])

@app.route('/api/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    product = Product.query.get_or_404(product_id)
    return jsonify({'id': product.id, 'name': product.name, 'category': product.category, 'price': product.price, 'description': product.description, 'imageUrl': product.imageUrl})

@app.route('/api/products', methods=['POST'])
@jwt_required()
def add_product():
    data = request.json
    new_product = Product(name=data['name'], category=data['category'], price=data['price'], description=data.get('description'), imageUrl=data.get('imageUrl'))
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'message': 'Product added successfully', 'id': new_product.id}), 201

@app.route('/api/products/<int:product_id>', methods=['PUT'])
@jwt_required()
def update_product(product_id):
    product = Product.query.get_or_404(product_id)
    data = request.json
    product.name = data['name']
    product.category = data['category']
    product.price = data['price']
    product.description = data.get('description')
    product.imageUrl = data.get('imageUrl')
    db.session.commit()
    return jsonify({'message': 'Product updated successfully'}), 200

@app.route('/api/products/<int:product_id>', methods=['DELETE'])
@jwt_required()
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    return jsonify({'message': 'Product deleted successfully'}), 200

# Social Link Management
@app.route('/api/sociallinks', methods=['GET'])
def get_social_links():
    links = SocialLink.query.all()
    return jsonify([{'id': l.id, 'platform': l.platform, 'url': l.url} for l in links])

@app.route('/api/sociallinks/<int:link_id>', methods=['GET'])
def get_social_link(link_id):
    link = SocialLink.query.get_or_404(link_id)
    return jsonify({'id': link.id, 'platform': link.platform, 'url': link.url})

@app.route('/api/sociallinks', methods=['POST'])
@jwt_required()
def add_social_link():
    data = request.json
    new_link = SocialLink(platform=data['platform'], url=data['url'])
    db.session.add(new_link)
    db.session.commit()
    return jsonify({'message': 'Social link added successfully', 'id': new_link.id}), 201

@app.route('/api/sociallinks/<int:link_id>', methods=['PUT'])
@jwt_required()
def update_social_link(link_id):
    link = SocialLink.query.get_or_404(link_id)
    data = request.json
    link.platform = data['platform']
    link.url = data['url']
    db.session.commit()
    return jsonify({'message': 'Social link updated successfully'}), 200

@app.route('/api/sociallinks/<int:link_id>', methods=['DELETE'])
@jwt_required()
def delete_social_link(link_id):
    link = SocialLink.query.get_or_404(link_id)
    db.session.delete(link)
    db.session.commit()
    return jsonify({'message': 'Social link deleted successfully'}), 200

# Serve HTML templates
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin')
def admin():
    return render_template('admin.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
