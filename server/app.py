from flask import Flask, render_template, request, url_for, redirect, session
import pymongo
import bcrypt
import certifi
import sys
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
# <client_credentials>
ca = certifi.where()
CONNECTION_STRING= "mongodb://newsbytes:sQ8hYWggAhkmRYD35ltNwfYwhmhxrBDBmHGzPPt041yTJv0nxOmXHnhU192qt8AEhDYXZM2NYn4rACDb5J2MpA==@newsbytes.mongo.cosmos.azure.com:10255/?ssl=true&retrywrites=false&replicaSet=globaldb&maxIdleTimeMS=120000&appName=@newsbytes@"
# </client_credentials>

DB_NAME = "newsbytes"
COLLECTION_NAME = "users"


try:
    # <connect_client>
    client = pymongo.MongoClient(CONNECTION_STRING, tlsCAFile = ca)
    # </connect_client>

    try:
        client.server_info()  # validate connection string
    except (
        pymongo.errors.OperationFailure,
        pymongo.errors.ConnectionFailure,
        pymongo.errors.ExecutionTimeout,
    ) as err:
        sys.exit("Can't connect:" + str(err))
except Exception as err:
    sys.exit("Error:" + str(err))

def get_db(db_name = DB_NAME):
    db = client[db_name]
    if DB_NAME not in client.list_database_names():
        db.command({"customAction": "CreateDatabase", "offerThroughput": 400})
        print("Created db '{}' with shared throughput.\n".format(DB_NAME))
    else:
        print("Using database: '{}'.\n".format(DB_NAME))
    
    return db



app.secret_key = "testing"
db = get_db(DB_NAME)
records = db[COLLECTION_NAME]

@app.route("/")
def main():
    return 'Aaru'

@app.route("/register", methods = ["POST"], strict_slashes=False)
def index():
    msg = ''
    #if request.method == "POST":
        #user = request.form.get("name")
        #email = request.form.get("email")

    user = request.json['name']
    email = request.json['email']

        #password1 = request.form.get("password1")
        #password2 = request.form.get("password2")

    password1 = request.json['password1']
    password2 = request.json['password2']

    preferences = request.json['preferences']

    user_found = records.find_one({"name": user})
    email_found = records.find_one({"email": email})

    if user_found:
        msg = 'There already is a user by that name'
        
    if email_found:
        msg = 'This email already exists'

    if password1 != password2:
        msg = 'Passwords should match'
    else:
        #hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
        user_input = {'name': user, 'email': email, 'password': hashed, 'preferences':preferences}
        #records.insert_one(user_input)
        print(user_input)

        #user_data = records.find_one({"email": email})
        #new_email = user_data['email']
        msg = 'Welcome to NewsBytes'

    return msg



@app.route('/login', methods = ["POST","GET"])
def login():
    msg = ' '
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        email_found = records.find_one({"email": email})
        if email_found:
            email_val = email_found['email']
            passwordcheck = email_found['password']
            
            if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
                session["email"] = email_val
                return 'User found'
            else:
                message = 'Wrong password'
                return msg

        else:
            msg = 'Email not found'
            return msg
    return msg


if __name__ == "__main__":
    app.run(port = 5000, debug = True)

