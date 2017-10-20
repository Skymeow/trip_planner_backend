import server
import unittest
import json
import bcrypt
import base64
import pdb
from pymongo import MongoClient
# for post request:
# password >6, check for existence of email,pssword
# for trips validate
# for put: complete, waypoint update works

def generateBasicAuthHeader(username, password):
        concatString = username + ':' + password
        utf8 = concatString.encode('utf-8')
        base64String = base64.b64encode(utf8)
        authString = base64String.decode('utf-8')
        finalString = "Basic " + authString
        return finalString

class TripPlannerTestCase(unittest.TestCase):


    def setUp(self):

      self.app = server.app.test_client()
      # Run app in testing mode to retrieve exceptions and stack traces
      server.app.config['TESTING'] = True

      mongo = MongoClient('localhost', 27017)
      global db

      # Reduce encryption workloads for tests
      server.app.bcrypt_rounds = 12

      db = mongo.trip_planner_test
      server.app.db = db

      db.drop_collection('user')
      db.drop_collection('trips')

    # User tests, fill with test methods
    # def test_get_user(self):
    #     post_resp = self.app.post('/users', headers=None,data=json.dumps(dict(username="sky", email="sky@gmail.com", password="password")), content_type="application/json")
    #     # response_id = json.loads(post_resp.data.decode())['_id']
    #     # response = self.app.get('/user', query_string=dict(user_id=response_id))
    #     # self.assertEqual(response.status_code, 201)
    #     response = self.app.get('/users', query_string=dict(email="sky@gmail.com", password="password"))
    #     response_json = json.loads(response.data.decode())
    #     self.assertEqual(response.status_code, 200)

    # def test_post_user(self):
    #     response = self.app.post('/users', headers=None,data=json.dumps(dict(username="sky", email="sky@gmail.com", password="password")), content_type="application/json")
    #     self.assertEqual(response.status_code, 201)

    def test_delete_user(self):
        response = self.app.post('/users', headers=None,data=json.dumps(dict(username="sky", email="sky@gmail.com", password="password")), content_type="application/json")
        header_code = generateBasicAuthHeader("sky@gmail.com", "password")
        delete_user = self.app.delete('/users', headers=dict(authorization=header_code), query_string=dict(email="sky@gmail.com"), content_type="application/json")
        self.assertEqual(delete_user.status_code, 204)

    # def test_post_trip(self):
    #     post_resp = self.app.post('/users', headers="Authorization=Basic c2t5QGdtYWlsLmNvbTpwYXNzd29yZA==",data=json.dumps(dict(username="sky", user_email="sky@gmail.com", password="password")), content_type="application/json")
    #     post = self.app.post('/trips', headers="Authorization=Basic c2t5QGdtYWlsLmNvbTpwYXNzd29yZA==", data=json.dumps(dict(trip_name="awesometrip1", start_time="09/10", destination="holland", user_email="sky@gmail.com")), content_type="application/json")
    #     self.assertEqual(post.status_code, 201)

    # def test_get_trip(self):
    #     post_resp = self.app.post('/users', headers="Authorization=Basic c2t5QGdtYWlsLmNvbTpwYXNzd29yZA==",data=json.dumps(dict(username="sky", email="sky@gmail.com", password="password")), content_type="application/json")
    #     post = self.app.post('/trips', headers="Authorization=Basic c2t5QGdtYWlsLmNvbTpwYXNzd29yZA==", data=json.dumps(dict(trip_name="awesometrip1", start_time="09/10", destination="holland", user_email="sky@gmail.com")), content_type="application/json")
    #     response = self.app.get('/trips', query_string=dict(user_email="sky@gmail.com"))
    #     response_json = json.loads(response.data.decode())
    #     self.assertEqual(response.status_code, 200)

    # def test_patch_trip(self):
    #     post_resp = self.app.post('/users', headers="Authorization=Basic c2t5QGdtYWlsLmNvbTpwYXNzd29yZA==",data=json.dumps(dict(username="sky", email="sky@gmail.com", password="password")), content_type="application/json")
    #     post = self.app.post('/trips', headers="Authorization=Basic c2t5QGdtYWlsLmNvbTpwYXNzd29yZA==", data=json.dumps(dict(trip_name="awesometrip1", start_time="09/10", destination="holland", user_email="sky@gmail.com")), content_type="application/json")
    #     response = self.app.patch('/trips', headers="Authorization=Basic c2t5QGdtYWlsLmNvbTpwYXNzd29yZA==", query_string=dict(user_email="sky@gmail.com"), data=json.dumps(dict(trip_name="awesometrip1", start_time="09/10", destination="holland", user_email="sky@gmail.com")), content_type="application/json")
    #     self.assertEqual(response.status_code, 200)

    # def test_delete_trip(self):
    #     post_resp = self.app.post('/users', headers="Authorization=Basic c2t5QGdtYWlsLmNvbTpwYXNzd29yZA==",data=json.dumps(dict(username="sky", email="sky@gmail.com", password="password")), content_type="application/json")
    #     post = self.app.post('/trips', headers="Authorization=Basic c2t5QGdtYWlsLmNvbTpwYXNzd29yZA==", data=json.dumps(dict(trip_name="awesometrip1", start_time="09/10", destination="holland", user_email="sky@gmail.com")), content_type="application/json")
    #     response = self.app.delete('/trips', headers="Authorization=Basic c2t5QGdtYWlsLmNvbTpwYXNzd29yZA==", query_string=dict(user_email="sky@gmail.com"), content_type="application/json")
    #     self.assertEqual(response.status_code, 204)






def create_signature(verification_token, payload_body):
    """ Create the signed message from verification_token and string_to_sign """
    verification_token = verification_token.encode('ascii')
    string_to_sign = payload_body.encode('utf-8')
    dig = HMAC(verification_token, msg=string_to_sign, digestmod=hashlib.sha256).digest()
    print(b64encode(dig))







if __name__ == '__main__':
    unittest.main()
