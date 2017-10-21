from flask import Flask, request, make_response, jsonify
from flask_restful import Resource, Api
from pymongo import MongoClient
from utils.mongo_json_encoder import JSONEncoder
from bson.objectid import ObjectId
import bcrypt
from bson.json_util import dumps
import pdb
import json
from functools import wraps

app = Flask(__name__)
# app.config.from_pyfile('config.cfg')
# mongo = MongoClient('localhost', 27017)
# app.db = mongo.trip_planner_development
# mongo = MongoClient(app.config['MONGO_CLIENT'])
mongo = MongoClient('mongodb://sky94:12345@ds227525.mlab.com:27525/trip_planner_real')
app.db = mongo.trip_planner_real
api = Api(app)
app.bcrypt_rounds = 12

# authenticate decorator

def auth_validation(email, user_password):
    """This function is called to check if a username /
    password combination is valid.
    """

    user_collection = app.db.user
    encodedPassword = user_password.encode('utf-8')
    user = user_collection.find_one({"email": email})
    if user is None:
        return({"error": "email not found"}, 404, None)
    db_password = user['password']
    user_id = user["_id"]
    if bcrypt.hashpw(encodedPassword, db_password) == db_password:
        return (user_id, 200, None)
    return (None, 400, None)

def auth_function(f):
    def wrapper(*args, **kwargs):
        auth = request.authorization
        validation = auth_validation(auth.username, auth.password)
        if validation[1] is 400:
            return ('Could not verify your access level for that URL.\n'
                    'You have to login with proper credentials', 400,
                    {'WWW-Authenticate': 'Basic realm="Login Required"'})
        else:
            # args is the argument we pass in the function,
            # validation[0] is the return value,
            # kwargs is whatever the rest we get back
            return f(*args, validation[0], **kwargs)
    return wrapper

## Write Resources here
class User(Resource):
    # for signup

    def post(self):
        # pdb.set_trace()
        new_user = request.json
        user_collection = app.db.user
        password = new_user.get('password')
        encodedPassword = password.encode('utf-8')
        hashed = bcrypt.hashpw(encodedPassword, bcrypt.gensalt(app.bcrypt_rounds))
        new_user['password'] = hashed
        print(hashed)
        if 'username' in new_user and 'email' in new_user and 'password' in new_user:
            result = user_collection.insert_one(new_user)
            new_user.pop('password')
            print('hash successed')
            return(new_user, 201, None)
        elif not 'username' in new_user:
            return({"error": "no username? you crazy"}, 400, None)
        elif not 'email' in new_user:
            return({"error": "no email? you crazy"}, 400, None)
        else:
            return("no sure why but you screwed up", 400, None)

    @auth_function
    def get(self,user_id):
        user_collection = app.db.user
        # auth = request.authorization
        # user = user_collection.find_one({"email": auth.username})
        user = user_collection.find_one({"_id": ObjectId(user_id)})
        if user is None:
            print('no user exists')
            return("sorry not matched", 404, None)
        else:
            user.pop('password')
            json_user = json.loads(dumps(user))
            return (json_user, 200, None)

    @auth_function
    def delete(self, user_id):
        user_collection = app.db.user
        user = user_collection.find_one({"_id": ObjectId(user_id)})
        if user == None:
            return("no email", 404, None)
        else:
            user_collection.remove(user)
            return('the user has been deleted', 204, None)



class Trip(Resource):

    @auth_function
    def post(self, user_id):
        # pdb.set_trace()
        trip_collection = app.db.trips
        # email = request.authorization.username
        new_trip = request.json
        result = trip_collection.insert_one(new_trip)
        new_trip['user_id'] = user_id
        trip_collection.save(new_trip)
        # inserted_id is the key word for the trip id whenever we create a new one
        if result.inserted_id != None:
            return(new_trip, 201, None)
        else:
            return(None, 404, None)




    @auth_function
    def get(self, user_id):
        # pdb.set_trace()
        trip_collection = app.db.trips
        # email = request.authorization.username
        trips_result = []
        trips = trip_collection.find({"user_id": ObjectId(user_id)})
        for trip in trips:
            trips_result.append(trip)
        if trips_result is not None:
            return(trips_result, 200, None)
        else:
            return("no trip exist", 404, None)

    # @auth_function
    # def patch(self, user_id):
    #     user_collection = app.db.user
    #     trip_collection = app.db.trips
    #     update_trip = request.json
    #     if ('trip_name' in update_trip and 'destination' in update_trip and 'start_time' in update_trip):
    #         update_name = update_trip['trip_name']
    #         update_destination = update_trip['destination']
    #         update_start_time = update_trip['start_time']
    #         user = user_collection.find_one({"_id": ObjectId(user_id)})
    #         if user == None:
    #             return("error", 404, None)
    #         else:
    #             trip = trip_collection.find_one({"user_email": email})
    #             trip['trip_name'] = update_name
    #             trip['destination'] = update_destination
    #             trip['start_time'] = update_start_time
    #             trip_collection.save(trip)
    #             return('success', 200, None)
    #     else:
    #         print('hey dumdum you forgot to put info in frontend')

    @auth_function
    def delete(self, user_id):
        trip_collection = app.db.trips
        trip_id = request.args.get("trip_id")
        trip = trip_collection.find({"user_id": ObjectId(user_id)})
        if trip == None:
            return('error', 404, None)
        else:
            trip_collection.delete_one({'_id': trip_id})
            return(None, 200, None)
        #     trips_result = dumps(list(trip))
        #     for trip in trips_result:
        #         if trip["_id"] == trip_id:
        #             trips_result.remove(trip)
        #         else:
        #             return("couldn't find trip that matches id", 404, None)
        #         pass
        # return(trip, 200, None)


## Add api routes here
api.add_resource(User, '/users')
api.add_resource(Trip, '/trips')
# '/user/<string:user_id>'
#this is part of json restful
#  Custom JSON serializer for flask_restful
#the application function is called first(before add route hits our function, decorator)
@api.representation('application/json')
def output_json(data, code, headers=None):
    resp = make_response(JSONEncoder().encode(data), code)
    resp.headers.extend(headers or {})
    return resp

if __name__ == '__main__':
    # Turn this on in debug mode to get detailled information about request
    # related exceptions: http://flask.pocoo.org/docs/0.10/config/
    app.config['TRAP_BAD_REQUEST_ERRORS'] = True
    app.run(debug=True)
