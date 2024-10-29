from flask import Flask, request, render_template, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
import bcrypt

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'  # Para gerenciar sessões

# Configuração do banco de dados SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
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
    session.pop('admin_logged_in', None)  # Remove a sessão do admin
    return redirect(url_for('admin_login'))  # Redireciona para o login do admin

# Página de cadastro (protegida pelo login de administrador)
@app.route('/register')
def register_page():
    if not session.get('admin_logged_in'):  # Protege a rota de cadastro
        return redirect(url_for('admin_login'))  # Redireciona para o login do admin
    return render_template('register.html')

# Rota para cadastro de usuários via HTML
@app.route('/register', methods=['POST'])
def register():
    if not session.get('admin_logged_in'):  # Protege o cadastro
        return redirect(url_for('admin_login'))  # Redireciona para o login do admin

    username = request.form['username']
    password = request.form['password']

    # Verifica se o usuário já existe
    if User.query.filter_by(username=username).first():
        return render_template('register.html', error="Usuário já existe!")

    # Cria novo usuário
    hashed_password = hash_password(password)
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return render_template('success.html', message="Usuário cadastrado com sucesso!")

# Rota para autenticação via HTML (após login do admin)
@app.route('/auth', methods=['POST'])
def auth_html():
    if not session.get('admin_logged_in'):  # Protege a rota de autenticação
        return redirect(url_for('admin_login'))  # Redireciona para o login do admin

    username = request.form.get('username')
    password = request.form.get('password')

    # Verifica se o usuário existe e se a senha está correta
    user = User.query.filter_by(username=username).first()
    if not user or not check_password(user.password, password):
        return render_template('index.html', error="Usuário ou senha inválidos.")
    
    return render_template('success.html', message="Autenticado com sucesso!")

# Rota de autenticação via JSON (API)
@app.route('/api/auth', methods=['POST'])
def auth_api():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    # Verifica se o usuário existe e se a senha está correta
    user = User.query.filter_by(username=username).first()
    if not user or not check_password(user.password, password):
        return jsonify({'message': 'Invalid username or password'}), 401

    return jsonify({'message': 'Authenticated successfully'}), 200

# Rota para remover usuários
@app.route('/remove_user', methods=['POST'])
def remove_user():
    if not session.get('admin_logged_in'):  # Protege a remoção de usuários
        return redirect(url_for('admin_login'))  # Redireciona para o login do admin

    username = request.form['username']

    # Verifica se o usuário existe
    user = User.query.filter_by(username=username).first()
    if not user:
        return render_template('success.html', message="Usuário não encontrado.")

    # Remove o usuário
    db.session.delete(user)
    db.session.commit()
    return render_template('success.html', message=f"Usuário {username} removido com sucesso.")

# Rota para exibir a página de sucesso
@app.route('/success')
def success_page():
    message = request.args.get('message', 'Ação realizada com sucesso!')
    return render_template('success.html', message=message)

if __name__ == '__main__':
    app.run(debug=True)
