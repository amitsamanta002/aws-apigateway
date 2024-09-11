import datetime
import json
import os
import subprocess
import sys

subprocess.call('pip install PyJWT pymongo -t /tmp/ --no-cache-dir'.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
sys.path.insert(1, '/tmp/')

import logging
import jwt
from pymongo import MongoClient

logger = logging.getLogger()
logger.setLevel(logging.INFO)

client = MongoClient(host= os.environ.get("MONGO_URI"))
# client = MongoClient("mongodb+srv://rishi:Rishi2021@cluster0.5cul8.mongodb.net/?retryWrites=true&w=majority")
def lambda_handler(event, context):
    action = 'Deny'
    user = None
    context = dict()
    try:
        bearer_token = event.get('authorizationToken')
        logger.info('bearer token = %s', bearer_token)
        token = bearer_token.replace('Bearer ', '')
        method = event.get('methodArn')
        logger.info('token = %s ', token)
        user_info = jwt.decode(token, "SsJehcjFElWgH43UFmVjgzbV87iEZX6VMO8VR80Eu4I=", algorithms=['HS512'])
        print("User info: ", user_info)
        logger.info("User info %s", user_info['sub'])
        logger.info("User info type %s", type(user_info))

        if len(user_info['sub']) is not None:
            db = client.usermanagement
            collection = db.userLogin
            result = collection.find_one({"_id": user_info['sub']})
            if result:
                database_epoc = int(result.get('loginTime').timestamp())
                token_epoc = user_info['iat'] 
                temp = datetime.datetime.fromtimestamp(token_epoc)
                logger.info("Database epoc: %d",database_epoc)
                logger.info("Token epoc: %d", token_epoc)
                if database_epoc <= token_epoc:
                    action = 'Allow'
                    user = user_info['sub']
                    context['statusCode'] = 200
                    context['body'] = "Authorized"
                    logger.info("User is authorized")
                elif database_epoc > token_epoc:
                    action = 'Deny'
                    user = user_info['sub']
                    context['statusCode'] = 409
                    context['body'] = "Multiple login detected. Current session is invalidated."
                    logger.info("Multiple login detected. Current session is invalidated.")
            else:
                logger.info("No user data found in database")
                context['statusCode'] = 403
                context['body'] = "User is not Authorized"
        else:
            context['statusCode'] = 403
            context['body'] = "User is not Authorized"
    except jwt.ExpiredSignatureError as es:
        context['statusCode'] = 401,
        context['body'] = 'Token Expired'

    except jwt.InvalidTokenError as ite:
        context['statusCode'] = 401,
        context['body'] = 'Invalid Token'
    except Exception as e:
        logging.exception(e)
        context['statusCode'] = 401,
        context['body'] = 'Invalid Credentials Please Login again'

    response = {
        "principalId": f"{user}",
        "policyDocument": {
        "Version": "2012-10-17",
        "Statement": [
        {
            "Action": "execute-api:Invoke",
            "Effect": f"{action}",
            "Resource": "arn:aws:execute-api:ap-south-1:191362498532:d6l5m7xuy6/*/*"
        },
        {
            "Action": "execute-api:Invoke",
            "Effect": f"{action}",
            "Resource": "arn:aws:execute-api:ap-south-1:191362498532:xl053jqm9l/*/*"
        }
        ]
      },
      "context": {"statusCode": f"{context['statusCode']}","body": f"{context['body']}"} 
    }
    return response
