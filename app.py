from flask import Flask, redirect, render_template, flash, url_for, redirect, request, send_file, jsonify
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flasgger import Swagger
from wtforms_flask_our import RegisterForm, LoginForm
from models import db, Files, Users
from file_functions import format_size
import os
import uuid
import re

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///project.db'
app.config['SECRET_KEY']="Super klucz tajnosci" #jest hardcoded ale gdyby bylo to w srodowisku produkcyjnym, wyrzucilbym na zmienna env
app.config['UPLOAD_FOLDER'] = 'uploads'
db.init_app(app)
migrate = Migrate(app,db)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

swagger = Swagger(app, template={
    "info": {
        "title": "API Projektu z Inżynierii Oprogramowania II",
        "description": "API aplikacji do zarządzania plikami użytkowników",
        "version": "1.0.0"
    },
    "schemes": ["http", "https"]
})

app.jinja_env.globals['format_size'] = format_size


@app.route('/')
def base_redir():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    """
    Zalogowanie użytkownika
    ---
    tags:
      - Autoryzacja
    parameters:
      - name: login_or_email
        in: formData
        type: string
        required: true
        description: Login lub email użytkownika
      - name: password
        in: formData
        type: string
        required: true
        description: Hasło użytkownika
    responses:
      302:
        description: Przekierowanie po udanym logowaniu lub nieudanym logowaniu
    """
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        login_or_email = form.login_or_email.data
        password = form.password.data

        user = Users.query.filter((Users.login == login_or_email) | (Users.email == login_or_email)).first()

        if user and user.verify_password(password):
            login_user(user)
            print(f"Zalogowano użytkownika: {user.login}, ID: {user.id}")
            flash('Logowanie przebiegło pomyślnie!', 'success')
            return redirect(url_for('dashboard'))        
        else:
            flash('Niepoprawny login lub hasło!', 'danger')

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET','POST'])
def register():
    """
    Rejestracja nowego użytkownika
    ---
    tags:
      - Autoryzacja
    parameters:
      - name: login
        in: formData
        type: string
        required: true
        description: Login użytkownika
      - name: email
        in: formData
        type: string
        required: true
        description: Email użytkownika
      - name: password_hash
        in: formData
        type: string
        required: true
        description: Hasło użytkownika (min. 15 znaków, musi zawierać małą i wielką literę, cyfrę oraz znak specjalny)
    responses:
      302:
        description: Przekierowanie po udanej rejestracji lub nieudanej rejestracji
    """
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegisterForm()
    if form.validate_on_submit():
        login = form.login.data
        email = form.email.data
        password = form.password_hash.data

        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{15,}$', password):
            flash('Hasło musi zawierać co najmniej jedną małą literę, jedną wielką literę, jedną cyfrę i jeden znak specjalny (!@#$%^&*)!', 'danger')
            return render_template('register.html', form=form)

        if Users.query.filter_by(email=email).first():
            flash('Ten e-mail jest już wykorzystany!', 'danger')
            return render_template('register.html', form=form)

        new_user = Users(login=login, email=email)
        new_user.password = password

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Rejestracja przebiegła pomyślnie, możesz się zalogować!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Wystąpił błąd w trakcie rejestracji', 'danger')
            print(f'Błąd w trakcie rejestracji użytkownika {login} error message: {str(e)}')

    return render_template('register.html', form=form)


@app.route('/logout')
@login_required
def logout():
    """
    Wylogowanie użytkownika
    ---
    tags:
      - Autoryzacja
    security:
      - Bearer: []
    responses:
      302:
        description: Przekierowanie po wylogowaniu
    """
    logout_user()
    flash('Wylogowałeś się', 'success')
    return redirect(url_for('login'))

@app.route('/user')
@login_required
def user_panel():
    """
    Panel użytkownika z informacjami o koncie
    ---
    tags:
      - Użytkownik
    security:
      - Bearer: []
    responses:
      200:
        description: Strona z panelem użytkownika
    """
    files = Files.query.filter_by(user_id=current_user.id).all()
    total_size = sum(file.size for file in files)
    file_count = len(files)
    formatted_size = format_size(total_size)  
    return render_template('user_panel.html', 
                           username=current_user.login, 
                           email=current_user.email, 
                           file_count=file_count, 
                           total_size=formatted_size)

@app.route('/dashboard')
@login_required
def dashboard():
    """
    Panel główny z listą plików użytkownika
    ---
    tags:
      - Pliki
    security:
      - Bearer: []
    responses:
      200:
        description: Strona panelu głównego z listą plików
    """
    files = Files.query.filter_by(user_id=current_user.id).all()

    print(f"Użytkownik: {current_user.login}, Autoryzowany: {current_user.is_authenticated}")
    return render_template('dashboard.html', 
                           login = current_user.login,
                           files = files)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """
    Przesyłanie pliku
    ---
    tags:
      - Pliki
    security:
      - Bearer: []
    consumes:
      - multipart/form-data
    parameters:
      - name: file
        in: formData
        type: file
        required: true
        description: Plik do przesłania
    responses:
      302:
        description: Przekierowanie po przesłaniu pliku
    """
    if 'file' not in request.files:
        flash('Brak pliku w żądaniu!', 'danger')
        return redirect(url_for('dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash('Nie wybrano pliku!', 'danger')
        return redirect(url_for('dashboard'))

    if file:
        stored_filename = str(uuid.uuid4())
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
        file.save(file_path)

        file_size = os.path.getsize(file_path) / (1024*1024)

        new_file = Files(
                original_filename=file.filename,
                stored_filename=stored_filename,
                size=file_size,
                user_id=current_user.id)
        try:
            db.session.add(new_file)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash('Wystąpił błąd w przesyłaniu pliku!', 'danger')
            print(f'Błąd w trakcie przesyłania pliku od użytkownika {current_user.login} error message: {str(e)}')

        flash('Plik został przesłany pomyślnie!', 'success')
        return redirect(url_for('dashboard'))

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    """
    Pobieranie pliku
    ---
    tags:
      - Pliki
    security:
      - Bearer: []
    parameters:
      - name: file_id
        in: path
        type: integer
        required: true
        description: ID pliku do pobrania
    responses:
      200:
        description: Pobieranie pliku
      404:
        description: Plik nie znaleziony
    """
    file = Files.query.filter_by(
        id=file_id, 
        user_id=current_user.id).first_or_404()
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.stored_filename)
    return send_file(
    file_path,
    as_attachment=True,
    download_name=file.original_filename)


@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    """
    Usuwanie pliku
    ---
    tags:
      - Pliki
    security:
      - Bearer: []
    parameters:
      - name: file_id
        in: path
        type: integer
        required: true
        description: ID pliku do usunięcia
    responses:
      302:
        description: Przekierowanie po usunięciu pliku
      404:
        description: Plik nie znaleziony
    """
    file = Files.query.filter_by(
    id = file_id,
    user_id=current_user.id).first_or_404()
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.stored_filename)

    try:
        if os.path.exists(file_path):
            os.remove(file_path)

        db.session.delete(file)
        db.session.commit()
        flash('Plik został usunięty pomyślnie!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Wystąpił błąd w trakcie usuwania pliku!', 'danger')
        print(f'Błąd w trakcie usuwania pliku {file.stored_filename} przez użytkownika {current_user.login} error message: {str(e)}')
    return redirect(url_for('dashboard'))


@app.route('/edit/<int:file_id>', methods=['GET', 'POST'])
@login_required
def edit_file(file_id):
    """
    Edycja pliku tekstowego
    ---
    tags:
      - Pliki
    security:
      - Bearer: []
    parameters:
      - name: file_id
        in: path
        type: integer
        required: true
        description: ID pliku do edycji
      - name: file_name
        in: formData
        type: string
        required: false
        description: Nowa nazwa pliku (tylko dla metody POST)
      - name: file_content
        in: formData
        type: string
        required: false
        description: Nowa zawartość pliku (tylko dla metody POST)
    responses:
      200:
        description: Zawartość pliku do edycji (dla metody GET)
      302:
        description: Przekierowanie po edycji pliku (dla metody POST)
      400:
        description: Błąd - nieprawidłowy format pliku do edycji
      404:
        description: Plik nie znaleziony
      500:
        description: Błąd serwera podczas odczytu/zapisu pliku
    """
    file = Files.query.filter_by(id=file_id, user_id=current_user.id).first_or_404()
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.stored_filename)

    text_extensions = ['.txt', '.md', '.log', '.csv']
    file_extension = os.path.splitext(file.original_filename)[1].lower()

    if file_extension not in text_extensions:
        return jsonify({'error': 'Edycja tego pliku jest niemożliwa! Możesz edytować tylko pliki tekstowe (.txt, .md, .log, .csv), aby uniknąć uszkodzenia pliku.'}), 400

    if request.method == 'GET':
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return jsonify({
                'file_name': file.original_filename,
                'file_content': content,
                'file_id': file.id
            })
        except Exception as e:
            return jsonify({'error': f'Nie udało się wczytać zawartości pliku: {str(e)}'}), 500

    elif request.method == 'POST':
        new_filename = request.form.get('file_name')
        new_content = request.form.get('file_content')

        if not new_filename or not new_content:
            flash('Nazwa pliku i zawartość nie mogą być puste!', 'danger')
            return redirect(url_for('dashboard'))

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            
            file.original_filename = new_filename
            file.size = os.path.getsize(file_path) / (1024 * 1024)
            db.session.commit()
            flash('Plik został zaktualizowany pomyślnie!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Wystąpił błąd podczas zapisywania pliku: {str(e)}', 'danger')

        return redirect(url_for('dashboard'))



@app.route('/update_username', methods=['POST'])
@login_required
def update_username():
    """
    Aktualizacja nazwy użytkownika
    ---
    tags:
      - Użytkownik
    security:
      - Bearer: []
    parameters:
      - name: currentPassword
        in: formData
        type: string
        required: true
        description: Aktualne hasło użytkownika
      - name: newUsername
        in: formData
        type: string
        required: true
        description: Nowa nazwa użytkownika
      - name: confirmNewUsername
        in: formData
        type: string
        required: true
        description: Potwierdzenie nowej nazwy użytkownika
    responses:
      302:
        description: Przekierowanie po aktualizacji nazwy użytkownika
    """
    current_password = request.form.get('currentPassword')
    new_username = request.form.get('newUsername')
    confirm_username = request.form.get('confirmNewUsername')

    if not current_password or not new_username or not confirm_username:
        flash('Wszystkie pola są wymagane!', 'danger')
        return redirect(url_for('user_panel'))

    if not current_user.verify_password(current_password):
        flash('Aktualne hasło jest nieprawidłowe!', 'danger')
        return redirect(url_for('user_panel'))

    if new_username != confirm_username:
        flash('Nowa nazwa użytkownika i potwierdzenie nie zgadzają się!', 'danger')
        return redirect(url_for('user_panel'))

    if len(new_username) > 20:
        flash('Nazwa użytkownika nie może przekraczać 20 znaków!', 'danger')
        return redirect(url_for('user_panel'))

    try:
        current_user.login = new_username
        db.session.commit()
        flash('Nazwa użytkownika została zaktualizowana pomyślnie!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Wystąpił błąd podczas aktualizacji nazwy użytkownika!', 'danger')
        print(f'Błąd podczas aktualizacji loginu użytkownika {current_user.login}: {str(e)}')

    return redirect(url_for('user_panel'))

@app.route('/update_email', methods=['POST'])
@login_required
def update_email():
    """
    Aktualizacja adresu email
    ---
    tags:
      - Użytkownik
    security:
      - Bearer: []
    parameters:
      - name: currentPassword
        in: formData
        type: string
        required: true
        description: Aktualne hasło użytkownika
      - name: newEmail
        in: formData
        type: string
        required: true
        description: Nowy adres email
      - name: confirmNewEmail
        in: formData
        type: string
        required: true
        description: Potwierdzenie nowego adresu email
    responses:
      302:
        description: Przekierowanie po aktualizacji adresu email
    """
    current_password = request.form.get('currentPassword')
    new_email = request.form.get('newEmail')
    confirm_email = request.form.get('confirmNewEmail')

    if not current_password or not new_email or not confirm_email:
        flash('Wszystkie pola są wymagane!', 'danger')
        return redirect(url_for('user_panel'))

    if not current_user.verify_password(current_password):
        flash('Aktualne hasło jest nieprawidłowe!', 'danger')
        return redirect(url_for('user_panel'))

    if new_email != confirm_email:
        flash('Nowy email i potwierdzenie nie zgadzają się!', 'danger')
        return redirect(url_for('user_panel'))

    if Users.query.filter_by(email=new_email).first() and new_email != current_user.email:
        flash('Ten adres email jest już używany!', 'danger')
        return redirect(url_for('user_panel'))

    try:
        current_user.email = new_email
        db.session.commit()
        flash('Adres email został zaktualizowany pomyślnie!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Wystąpił błąd podczas aktualizacji emaila!', 'danger')
        print(f'Błąd podczas aktualizacji emaila użytkownika {current_user.login}: {str(e)}')

    return redirect(url_for('user_panel'))

@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    """
    Aktualizacja hasła użytkownika
    ---
    tags:
      - Użytkownik
    security:
      - Bearer: []
    parameters:
      - name: currentPassword
        in: formData
        type: string
        required: true
        description: Aktualne hasło użytkownika
      - name: newPassword
        in: formData
        type: string
        required: true
        description: Nowe hasło (min. 15 znaków, musi zawierać małą i wielką literę, cyfrę oraz znak specjalny)
      - name: confirmPassword
        in: formData
        type: string
        required: true
        description: Potwierdzenie nowego hasła
    responses:
      302:
        description: Przekierowanie po aktualizacji hasła
    """
    current_password = request.form.get('currentPassword')
    new_password = request.form.get('newPassword')
    confirm_password = request.form.get('confirmPassword')

    if not current_password or not new_password or not confirm_password:
        flash('Wszystkie pola są wymagane!', 'danger')
        return redirect(url_for('user_panel'))

    if not current_user.verify_password(current_password):
        flash('Aktualne hasło jest nieprawidłowe!', 'danger')
        return redirect(url_for('user_panel'))

    if new_password != confirm_password:
        flash('Nowe hasło i potwierdzenie nie zgadzają się!', 'danger')
        return redirect(url_for('user_panel'))

    if len(new_password) < 15:
        flash('Hasło musi mieć minimum 15 znaków!', 'danger')
        return redirect(url_for('user_panel'))

    if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{15,}$', new_password):
        flash('Hasło musi zawierać co najmniej jedną małą literę, jedną wielką literę, jedną cyfrę i jeden znak specjalny (!@#$%^&*)!', 'danger')
        return redirect(url_for('user_panel'))

    try:
        current_user.password = new_password 
        db.session.commit()
        flash('Hasło zostało zaktualizowane pomyślnie!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Wystąpił błąd podczas aktualizacji hasła!', 'danger')
        print(f'Błąd podczas aktualizacji hasła użytkownika {current_user.login}: {str(e)}')

    return redirect(url_for('user_panel'))

@app.route('/preview/<int:file_id>', methods=['GET'])
@login_required
def preview_file(file_id):
    """
    Podgląd zawartości pliku tekstowego
    ---
    tags:
      - Pliki
    security:
      - Bearer: []
    parameters:
      - name: file_id
        in: path
        type: integer
        required: true
        description: ID pliku do podglądu
    responses:
      200:
        description: Zawartość pliku 
        schema:
          type: object
          properties:
            file_name:
              type: string
              description: Nazwa pliku
            file_content:
              type: string
              description: Zawartość pliku
            file_id:
              type: integer
              description: ID pliku
      400:
        description: Błąd - nieprawidłowy format pliku do podglądu
      404:
        description: Plik nie znaleziony
      500:
        description: Błąd serwera podczas odczytu pliku
    """
    file = Files.query.filter_by(id=file_id, user_id=current_user.id).first_or_404()
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.stored_filename)

    text_extensions = ['.txt', '.md', '.log', '.csv']
    file_extension = os.path.splitext(file.original_filename)[1].lower()

    if file_extension not in text_extensions:
        return jsonify({'error': 'Podgląd tego pliku jest niemożliwy! Możesz przeglądać tylko pliki tekstowe (.txt, .md, .log, .csv). Pobierz plik, aby zobaczyć jego zawartość.'}), 400

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify({
            'file_name': file.original_filename,
            'file_content': content,
            'file_id': file.id
        })
    except Exception as e:
        return jsonify({'error': f'Nie udało się wczytać zawartości pliku: {str(e)}'}), 500

@app.errorhandler(401)
def unauthorized(error):
    """
    Obsługa błędu 401 - Brak autoryzacji
    ---
    tags:
      - Błędy
    responses:
      401:
        description: Błąd autoryzacji
    """
    if not current_user.is_authenticated:
        flash('Błąd 401: Nie jesteś zalogowany. Zaloguj się, aby uzyskać dostęp.', 'danger')
        return redirect(url_for('login'))
    return render_template('error.html', code=401, message="Błąd 401: Brak autoryzacji. Skontaktuj się z administratorem."), 401

@app.errorhandler(404)
def not_found(error):
    """
    Obsługa błędu 404 - Nie znaleziono
    ---
    tags:
      - Błędy
    responses:
      404:
        description: Strona lub zasób nie znaleziony
    """
    return render_template('error.html', code=404, message="Błąd 404: Strona lub zasób nie znaleziony. Skontaktuj się z administratorem, jeśli uważasz, że to błąd."), 404

@app.errorhandler(500)
def internal_server_error(error):
    """
    Obsługa błędu 500 - Wewnętrzny błąd serwera
    ---
    tags:
      - Błędy
    responses:
      500:
        description: Wewnętrzny błąd serwera
    """
    return render_template('error.html', code=500, message="Błąd 500: Wystąpił problem wewnętrzny serwera. Proszę poinformować administratora o tym błędzie."), 500

# Dodanie dokumentacji API dla modeli
"""
models:
  Users:
    type: object
    properties:
      id:
        type: integer
        description: Unikalny identyfikator użytkownika
      login:
        type: string
        description: Login użytkownika
      email:
        type: string
        description: Adres email użytkownika
      password_hash:
        type: string
        description: Zahaszowane hasło użytkownika
  Files:
    type: object
    properties:
      id:
        type: integer
        description: Unikalny identyfikator pliku
      original_filename:
        type: string
        description: Oryginalna nazwa pliku
      stored_filename:
        type: string
        description: Nazwa pliku na serwerze (UUID)
      size:
        type: number
        format: float
        description: Rozmiar pliku w MB
      user_id:
        type: integer
        description: ID użytkownika, do którego należy plik
"""

if __name__ == '__main__':
    app.run(debug=True)
