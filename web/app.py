from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import json
import requests
import subprocess

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.ImageRecognition
users = db["Users"]


def UserExist(username):
    if users.find({"Username": username}).count() == 0:
        return False
    else:
        return True


class Register(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        if UserExist(username):
            retJson = {
                "status": 301,
                "msg": "Invalid Username"
            }

            return jsonify(retJson)

        hashed_pw = bcrypt.hashpw(password.encode("utf8"), bcrypt.gensalt())

        users.insert({
            "Username": username,
            "Password": hashed_pw,
            "Tokens": 4
        })

        retJson = {
            "status": 200,
            "msg": "User Registered"
        }

        return jsonify(retJson)


def verifyPassword(username, password):
    if not UserExist(username):
        return False

    hashed_pw = users.find({
        "Username": username
    })[0]["Password"]

    if bcrypt.hashpw(password.encode("utf8"), hashed_pw) == hashed_pw:
        return True
    else:
        return False

def getReturnJson(status, msg):
    retJson = {
        "status": status,
        "msg": msg
    }

    return retJson

def verifyUser(username, password):
    if not UserExist(username):
        return getReturnJson("301", "Invalid Username"), True
    correctPassword = verifyPassword(username, password)
    if not correctPassword:
        return getReturnJson("302", "Invalid Password"), True
    return None, False


class Classify(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        url = postedData["url"]

        retJson, error = verifyUser(username, password)

        if error:
            return jsonify(retJson)

        tokens = users.find({
            "Username": username
        })[0]["Tokens"]

        if tokens <= 0:
            return (getReturnJson(303, "Not Enough Tokens"))

        r = requests.get(url)

        with open("temp.jpg", "wb") as f:
            f.write(r.content)
            proc = subprocess.Popen(
                'python classify_image.py --model_dir=. --image_file=./temp.jpg')
            proc.communicate()[0]
            proc.wait()
            with open("text.txt") as g:
                retJson = json.load(g)

        users.update({
            "Username": username
        }, {
            "$set": {
                "Tokens": tokens - 1
            }
        })
        return retJson
