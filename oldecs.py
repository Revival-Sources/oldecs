from flask import Flask, request, send_file, redirect, make_response, abort
# from flask import Flask, request, redirect, make_response
import psycopg2
import os
import datetime
import random
import string
app = Flask(__name__)
staffList = [1,2,3]
def get_db_connection():
    conn = psycopg2.connect(
        host="localhost",
        database="bloxie",
        user="postgres",
        password="bloxie@"
    )
    return conn
import secrets
import string

def generate_cookie_string(length):
    cookie_characters = string.ascii_letters + string.digits + '-._~'
    return ''.join(secrets.choice(cookie_characters) for _ in range(length))

import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

@app.route("/Game/Join.ashx", methods=['GET'])
async def game_join():
    if 'cookie' not in request.args:
        abort(400, "Cookie is missing")

    cookie_query = request.args.get('cookie')
    format_string = "--rbxsig%{0}%{1}" if True else "%{0}%{1}"

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE cookie = %s", (cookie_query,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if user is None:
        return "User not found", 404

    username = user[2]
    user_id = user[1]

    script_path = "pages/join.ashx"
    with open(script_path, 'r') as file:
        script = "\r\n" + file.read()

    # Perform the necessary replacements in the script
    script = script.replace("USERNAMEHERE", username)
    script = script.replace("USERIDHERE", str(user_id))
    script = script.replace("MEMBERSHIPTYPEHERE", str(user[4]) if user[4] else "None")

    # Convert the script to bytes
    script_bytes = script.encode('utf-8')

    # Generate an RSA private key (if you don't already have one)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Sign the script using the private key and SHA-1 hashing algorithm
    signature = private_key.sign(
        script_bytes,
        padding.PKCS1v15(),
        hashes.SHA1()
    )

    # Encode the signature in base64
    signature_base64 = base64.b64encode(signature).decode('utf-8')

    # Format the script with the base64 signature
    script = format_string.format(signature_base64, script)
    return script, 200, {"Content-Type": "application/json"}
    

@app.route("/Game/PlaceLauncher.ashx", methods=['GET'])
async def game_place_launcher():
    if 'cookie' not in request.args:
        abort(400, "Cookie is missing")

    cookie_query = request.args.get('cookie')
    file_path = "pages/PlaceLauncher.ashx"
    # Path.Combine(Directory.GetCurrentDirectory(), "pages", "PlaceLauncher.ashx")
    with open(file_path, 'r') as file:
        file_content = file.read()
    file_content = file_content.replace("?cookie=cookie", f"?cookie={cookie_query}")
    file_content = file_content.replace("cookie=cookie", cookie_query)
    response = make_response(file_content)
    response.headers["Content-Type"] = "application/json"
    
    return response
    # updated = File.ReadAllText(Path.Combine(Directory.GetCurrentDirectory(), "pages", "PlaceLauncher.ashx"))

    # file_path = os.path.join(app.root_path, "pages", ".cshtml")
    # with open(file_path, 'r') as file:
        # file_content = file.read()
        
    return updated

@app.route("/Login/Negotiate.ashx", methods=['GET'])
async def login_negotiate():
    file_path = "pages/negotiate.ashx"
    with open(file_path, 'r') as file:
        file_content = file.read()
    response = make_response(file_content)
    response.headers["Content-Type"] = "application/json"
    
    return response

@app.route("/Setting/QuietGet/ClientAppSettings", methods=['GET'])
async def setting_client_app_settings():
    file_path = "pages/fflags.cshtml"
    with open(file_path, 'r') as file:
        file_content = file.read()
    response = make_response(file_content)
    response.headers["Content-Type"] = "application/json"
    
    return response

@app.route("/Setting/QuietGet/ClientSharedSettings", methods=['GET'])
async def setting_client_shared_settings():
    file_path = "pages/fflags.cshtml"
    with open(file_path, 'r') as file:
        file_content = file.read()
    response = make_response(file_content)
    response.headers["Content-Type"] = "application/json"
    
    return response

@app.route("/Game/Visit.ashx", methods=['GET'])
async def game_visit():
    file_path = "pages/visit.ashx"
    with open(file_path, 'r') as file:
        file_content = file.read()
    response = make_response(file_content)
    response.headers["Content-Type"] = "application/json"
    
    return response

@app.route("/game/validate-machine", methods=['GET'])
async def game_validate_machine():
    file_path = "pages/validatemachine.cshtml"
    with open(file_path, 'r') as file:
        file_content = file.read()
    response = make_response(file_content)
    response.headers["Content-Type"] = "application/json"
    
    return response


@app.route("/Game/GetCurrentUser.ashx", methods=['GET'])
async def game_get_current_user():
    file_path = "pages/currentuser.ashx"
    with open(file_path, 'r') as file:
        file_content = file.read()
    response = make_response(file_content)
    response.headers["Content-Type"] = "application/json"
    
    return response

@app.route("/Asset/CharacterFetch.ashx", methods=['GET'])
async def asset_character_fetch():
    userid = request.args.get('userId')
    file_path = "pages/fetch.cshtml"
    with open(file_path, 'r') as file:
        file_content = file.read()
    response = make_response(file_content)
    response.headers["Content-Type"] = "application/json"
    
    return response

@app.route("/logout", methods=['GET'])
def logout():
    response = make_response()
    response.delete_cookie("OLDECS_SECURITY")
    response.headers["Location"] = "/login"
    response.status_code = 302
    return response

@app.route("/ownership/hasasset/<path:path>", methods=['GET'])
def has_asset(path):
    return "true"

@app.route("/Thumbs/Avatar.ashx", methods=['GET'])
def avatar():
    user_id = request.args.get("userId")
    return redirect("/static/img/placeholder.png")

@app.route("/Thumbs/Asset.ashx", methods=['GET'])
def asset():
    user_id = request.args.get("userId")
    return redirect("/static/img/placeholder.png")

@app.route("/static/img/placeholder.png", methods=['GET'])
def placeholder():
    return app.send_static_file("Avatars/placeholder.png")

def gen_random_string(length):
    letters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(letters) for _ in range(length))


@app.route("/", methods=['GET'])
def home():
    if "OLDECS_SECURITY" in request.cookies:
        return redirect("/home")

    username = request.args.get("username", "")
    password = request.args.get("password", "")
    print(f"Signing up using: username {username} password {password}")

    if username and password:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get the highest ID from the users table
        cursor.execute("SELECT MAX(id) FROM users")
        highest_id = cursor.fetchone()[0]

        # Generate the new user ID
        user_id = highest_id + 1 if highest_id else 1

        # Generate a cookie for the user
        cookie = generate_cookie_string(500)

        # Insert the new user into the database
        insert_query = "INSERT INTO users (id, username, password, cookie, membership, robux, tix) VALUES (%s, %s, %s, %s, %s, %s, %s)"
        cursor.execute(insert_query, (user_id, username, password, cookie, "None", 100, 0))
        conn.commit()

        cursor.close()
        conn.close()

        cookie_options = {
            "expires": datetime.datetime.now() + datetime.timedelta(days=100),
            "secure": True,
            "httponly": True
        }
        response = make_response(redirect("/home"))
        response.set_cookie("OLDECS_SECURITY", cookie, **cookie_options)
        return response

    file_path = os.path.join(app.root_path, "pages", "signup.cshtml")
    with open(file_path, 'r') as file:
        file_content = file.read()
    return file_content

import os
import requests

@app.route("/asset", methods=['GET'])
def asset_migration():
    asset_id = request.args.get("id")

    # Check if the asset already exists in the "Assets" folder
    asset_path = f"Assets/{asset_id}"
    if os.path.exists(asset_path):
        # Asset already exists, send the file as the response
        return send_file(asset_path)

    # Asset doesn't exist, initiate migration and download
    asset_url = f"https://assetdelivery.roblox.com/v1/asset/?id={asset_id}"
    response = requests.get(asset_url)

    if response.status_code == 200:
        # Download the asset to the "Assets" folder
        with open(asset_path, 'wb') as file:
            file.write(response.content)

        # Send the downloaded asset as the response
        return send_file(asset_path)

    # Unable to download the asset
    return abort(400, "Failed to download asset")
@app.route("/asset/", methods=['GET'])
def asset_migration2():
    asset_id = request.args.get("id")

    # Check if the asset already exists in the "Assets" folder
    asset_path = f"Assets/{asset_id}"
    if os.path.exists(asset_path):
        # Asset already exists, send the file as the response
        return send_file(asset_path)

    # Asset doesn't exist, initiate migration and download
    asset_url = f"https://assetdelivery.roblox.com/v1/asset/?id={asset_id}"
    response = requests.get(asset_url)

    if response.status_code == 200:
        # Download the asset to the "Assets" folder
        with open(asset_path, 'wb') as file:
            file.write(response.content)

        # Send the downloaded asset as the response
        return send_file(asset_path)

    # Unable to download the asset
    return abort(400, "Failed to download asset")

@app.route("/joinscript", methods=['GET'])
def join_script():
    cookie = request.cookies.get("OLDECS_SECURITY")
    
    if not cookie:
        return "OLDECS_SECURITY cookie not found."

    # Construct the join script
    join_script = f'-t "{cookie}" -a "https://www.oldecs.com/Login/Negotiate.ashx" -j "https://www.oldecs.com/Game/Join.ashx?cookie={cookie}"'
    
    response = make_response(join_script)
    response.headers["Content-Type"] = "application/json"
    
    return response
@app.route("/login", methods=['GET'])
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    print(f"Logging in using: username {username} password {password}")

    if username and password:
        # Database operations to validate user credentials
        # ...
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if user[2] == password:

            cookie = user[3]  # Get the user's cookie from the database
            cookie_options = {
                "expires": datetime.datetime.now() + datetime.timedelta(days=100),
                "secure": True,
                "httponly": True
            }
            response = make_response(redirect("/home"))
            response.set_cookie("OLDECS_SECURITY", cookie, **cookie_options)
            return response

    file_path = os.path.join(app.root_path, "pages", "login.cshtml")
    with open(file_path, 'r') as file:
        file_content = file.read()
    return file_content
@app.route("/game/players/<path:path>", methods=['GET'])
def game_players(path):
    file_path = os.path.join(app.root_path, "pages", "gameplayers.ashx")
    with open(file_path, 'r') as file:
        file_content = file.read()
    return file_content

@app.route("/users/<path:path>", methods=['GET'])
def users(path):
    file_path = os.path.join(app.root_path, "pages", "canmanage.ashx")
    with open(file_path, 'r') as file:
        file_content = file.read()
    return file_content

@app.route("/GetAllowedMD5Hashes", methods=['GET'])
def allowed_md5_hashes():
    file_path = os.path.join(app.root_path, "pages", "allowedmd5hashes.ashx")
    with open(file_path, 'r') as file:
        file_content = file.read()
    return file_content

@app.route("/home", methods=['GET'])
def homes():
    cookie_value = request.cookies.get("OLDECS_SECURITY")
    if cookie_value is not None:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE cookie = %s", (cookie_value,))
        user = cursor.fetchone()
        # print(user[3])

        cursor.close()
        conn.close()

        if user is not None:
            file_path = os.path.join(app.root_path, "pages", "home.cshtml")
            with open(file_path, 'r') as file:
                file_content = file.read()

            file_content = file_content.replace("Username", user[1])
            if user[0] in staffList:
                file_content = file_content.replace("Membership", "Administrator")
            elif user[4] == "OutrageousBuildersClub":
                file_content = file_content.replace("Membership", "OBC")
            elif user[4] == "TurboBuildersClub":
                file_content = file_content.replace("Membership", "TBC")
            elif user[4] == "BuildersClub":
                file_content = file_content.replace("Membership", "BC")
            else:
                file_content = file_content.replace("(Membership)", "")
            file_content = file_content.replace("ROBUXHERE", str(user[5]))
            file_content = file_content.replace("TIXHERE", str(user[6]))

            return file_content
        else:
            return redirect("/login")
    else:
        return redirect("/login")

@app.route("/membership", methods=['GET'])
def membership():
    file_path = os.path.join(app.root_path, "pages", "membership.cshtml")
    cookie_value = request.cookies.get("OLDECS_SECURITY")
    if cookie_value is not None:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE cookie = %s", (cookie_value,))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if user is not None:
            file_path = os.path.join(app.root_path, "pages", "membership.cshtml")
            with open(file_path, 'r') as file:
                file_content = file.read()
            return file_content
    return ""


def get_db_context():
    # Function to create and return the database context
    # Replace with your own implementation
    return get_db_connection()

def read_file_content(file_path):
    with open(file_path, 'r') as file:
        return file.read()

if __name__ == "__main__":
    app.run(port=4000)