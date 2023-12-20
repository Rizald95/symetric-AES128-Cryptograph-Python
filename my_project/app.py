import os
from flask import Flask, render_template, request, redirect, url_for
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from werkzeug.utils import secure_filename
import logging

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def openssl_encrypt(message, key):
    if isinstance(message, bytes):
        message = message.decode('utf-8')

    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return cipher.iv + ciphertext


# Konfigurasi logging (tambahkan di bagian atas program)
logging.basicConfig(filename='app.log', level=logging.ERROR)


def openssl_decrypt(encrypted_message, key):
    iv = encrypted_message[:AES.block_size]
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_message = unpad(cipher.decrypt(
            encrypted_message[AES.block_size:]), AES.block_size)
        return decrypted_message.decode('utf-8')
    except Exception as e:
        # Log kesalahan
        logging.error(f"Error decrypting message: {e}")
        return "Error decrypting message"


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        message = request.form['message']
        key = os.urandom(16)  # AES 128-bit key

        encrypted_message = openssl_encrypt(message, key)

        return render_template('encrypt.html', message=message, key=key, encrypted_message=encrypted_message)

    return render_template('encrypt_form.html')


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            with open(filepath, 'rb') as f:
                file_contents = f.read()

            key = os.urandom(16)
            encrypted_contents = openssl_encrypt(file_contents, key)

            encrypted_filename = 'encrypted_' + filename
            encrypted_filepath = os.path.join(
                app.config['UPLOAD_FOLDER'], encrypted_filename)

            key_filename = 'key_' + filename + '.txt'
            key_filepath = os.path.join(
                app.config['UPLOAD_FOLDER'], key_filename)
            with open(key_filepath, 'wb') as key_file:
                key_file.write(key)

            with open(encrypted_filepath, 'wb') as f:
                f.write(encrypted_contents)

            return render_template('upload.html', filename=filename, key_filename=key_filename, encrypted_filename=encrypted_filename)

    return render_template('upload_form.html')


@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        key_filename = request.form['key_filename']
        key_filepath = os.path.join(app.config['UPLOAD_FOLDER'], key_filename)
        with open(key_filepath, 'rb') as key_file:
            key = key_file.read()

        encrypted_message = request.form['encrypted_message']

        # Menangani file path jika diisi
        file_path = request.files['file_path']
        if file_path:
            file_path = secure_filename(file_path.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_path)
            with open(file_path, 'rb') as file_path_file:
                encrypted_message = file_path_file.read()

        try:
            decrypted_message = openssl_decrypt(encrypted_message, key)
        except Exception as e:
            print(f"Error decrypting message: {e}")
            decrypted_message = "Error decrypting message"

        return render_template('decrypt.html', key=key, encrypted_message=encrypted_message, decrypted_message=decrypted_message)

    return render_template('decrypt_form.html')

# ...


@app.route('/decrypt', methods=['POST'])
def decrypt_from_encrypt():
    if request.method == 'POST':
        key = request.form['key']
        encrypted_message = request.form['encrypted_message']

        try:
            decrypted_message = openssl_decrypt(encrypted_message, key)
        except Exception as e:
            print(f"Error decrypting message: {e}")
            decrypted_message = "Error decrypting message"

        return render_template('decrypt.html', key=key, encrypted_message=encrypted_message, decrypted_message=decrypted_message)

    return redirect(url_for('index'))


# ...

@app.route('/decrypt_message', methods=['POST'])
def decrypt_message():
    encrypted_message = request.form['encrypted_message']
    key = os.urandom(16)

    try:
        decrypted_message = openssl_decrypt(encrypted_message, key)
    except Exception as e:
        print(f"Error decrypting message: {e}")
        decrypted_message = "Error decrypting message"

    return render_template('encrypt.html', message='', key=key, encrypted_message=encrypted_message, decrypted_message=decrypted_message)

# ...


@app.route('/dashboard')
def dashboard():
    files = []
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        if filename.startswith('encrypted_'):
            encrypted_filepath = os.path.join(
                app.config['UPLOAD_FOLDER'], filename)
            decrypted_filepath = os.path.join(
                app.config['UPLOAD_FOLDER'], filename.replace('encrypted_', 'decrypted_'))

            files.append({
                'no': len(files) + 1,
                'source_filename': filename,
                'encrypted_filename': 'decrypted_' + filename,
                'path': os.path.abspath(encrypted_filepath),
                'status': 'Decrypted' if os.path.exists(decrypted_filepath) else 'Not Decrypted',
                'action_button': f'Decrypt {filename}'
            })

    return render_template('dashboard.html', files=files)


if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)
