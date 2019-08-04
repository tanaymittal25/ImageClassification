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