from flask import Flask, request, render_template, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import os

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'

# Configuração do banco de dados PostgreSQL
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    'postgresql://instapotion_user:e4gwb0Xh6WXBMtefvG0ndxAbS0inhtzp@dpg-ct6of7hu0jms739aq5r0-a.oregon-postgres.render.com/instapotion'  # Substitua pelo URL do Render
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Modelo de usuário
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)

with app.app_context():
    db.create_all()

# Funções de hash e verificação de senha
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(hashed_password, password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

# Página de login do administrador
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Verifica se o usuário e senha são corretos (admin hardcoded)
        if username == 'botAlchemy' and password == 'igordev':
            session['admin_logged_in'] = True  # Marca o admin como logado na sessão
            return redirect(url_for('home'))  # Redireciona para a página inicial após o login
        else:
            return render_template('admin_login.html', error="Usuário ou senha incorretos.")
    
    # Se não for um POST, renderiza o formulário de login
    return render_template('admin_login.html')

# Página inicial (protegida pelo login de administrador)
@app.route('/')
def home():
    if not session.get('admin_logged_in'):  # Verifica se o admin está logado
        return redirect(url_for('admin_login'))  # Redireciona para o login se o admin não estiver logado
    return render_template('index.html')  # Renderiza a página inicial se o admin estiver logado

# Rota para logout do admin
@app.route('/logout')
def logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

# Página de cadastro protegida pelo login de administrador
@app.route('/register')
def register_page():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    return render_template('register.html')

# Rota para cadastro de usuários via HTML
@app.route('/register', methods=['POST'])
def register():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    username = request.form['username']
    password = request.form['password']
    password_confirm = request.form['password_confirm']

    if password != password_confirm:
        return render_template('register.html', error="As senhas não coincidem!")

    if User.query.filter_by(username=username).first():
        return render_template('register.html', error="Usuário já existe!")

    hashed_password = hash_password(password)
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('success_page', message="Usuário cadastrado com sucesso!"))

# Rota para autenticação via HTML (após login do admin)
@app.route('/auth', methods=['POST'])
def auth_html():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    username = request.form.get('username')
    password = request.form.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not check_password(user.password, password):
        return render_template('index.html', error="Usuário ou senha inválidos.")
    
    return redirect(url_for('success_page', message="Autenticado com sucesso!"))

# Rota de autenticação via JSON (API)
@app.route('/api/auth', methods=['POST'])
def auth_api():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not check_password(user.password, password):
        return jsonify({'message': 'Invalid username or password'}), 401

    return jsonify({'message': 'Authenticated successfully'}), 200

# Rota para remover usuários
@app.route('/remove_user', methods=['POST'])
def remove_user():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    username = request.form['username']
    user = User.query.filter_by(username=username).first()

    if not user:
        return redirect(url_for('success_page', message="Usuário não encontrado."))

    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('success_page', message=f"Usuário {username} removido com sucesso."))

# Rota para exibir a página de sucesso com a lista de usuários
@app.route('/success')
def success_page():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    users = User.query.all()
    message = request.args.get('message', 'Ação realizada com sucesso!')
    return render_template('success.html', message=message, users=users)

if __name__ == '__main__':
    app.run(debug=True)
