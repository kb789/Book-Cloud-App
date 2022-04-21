import json
import os
from flask import Flask, request, jsonify, url_for, render_template
from flask_cors import CORS

from firebase_admin import credentials, firestore, auth
from flask_firebase_admin import FirebaseAdmin

import requests
from requests.auth import HTTPBasicAuth

import xml.etree.ElementTree as ET

import os

from wordcloud import WordCloud, STOPWORDS
import matplotlib.pyplot as plt

import base64
from io import BytesIO

from dotenv import load_dotenv
load_dotenv()



os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
CORS(app)

#cred = credentials.Certificate('key.json')
app.config["FIREBASE_ADMIN_CREDENTIAL"] = credentials.Certificate({
    "type": "service_account",
    "project_id": "bibliography-builder",
    "private_key_id": os.environ.get('private_key_id'),
    "private_key": os.environ.get('private_key').replace('\\n', '\n'),
    "client_email": os.environ.get('client_email'),
    "client_id": os.environ.get('client_id'),
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-f8pdn%40bibliography-builder.iam.gserviceaccount.com"

})
firebase = FirebaseAdmin(app)

db = firestore.client()
book_ref = db.collection('books')

key = os.environ.get('KEY')


@app.route('/getStats')
def getStats():
    try:
        auth_head = request.headers.get('Authorization')
        curr_id_token = auth_head[7:]
        decoded_token = auth.verify_id_token(curr_id_token)
        uid = decoded_token['uid']
        user_subjects = []
        query_ref = book_ref.where(u'user', u'==', uid)
        user_books = [doc.to_dict() for doc in query_ref.stream()]
        for book in user_books:
            for subject in book['subject']:
                user_subjects.append(subject['subjectName']['text'])
        subj_string = ""
        stopwords = set(STOPWORDS)
        for subj in user_subjects:
            tokens = subj.split()
            for i in range(len(tokens)):
                tokens[i] = tokens[i].lower()

            subj_string += " ".join(tokens) + " "
        wordcloud = WordCloud(width=800, height=800,
                              background_color='white',
                              stopwords=stopwords,
                              min_font_size=10).generate(subj_string)
        fig = plt.figure(figsize=(8, 8), facecolor=None)
        plt.imshow(wordcloud)
        plt.axis("off")
        plt.tight_layout(pad=0)

        tmpfile = BytesIO()
        fig.savefig(tmpfile, format='png')
        encoded = base64.b64encode(tmpfile.getvalue()).decode('utf-8')

        #response = jsonify(user_subjects)
        #return response
        return encoded
    except Exception as e:
        return f"An Error Occured: {e}"



def oclc2(isbn):
    try:
        client_id = os.environ.get('CLIENT_ID')
        client_secret = os.environ.get('CLIENT_SECRET')
        token_url = "https://oauth.oclc.org/token"
        scope = 'wcapi'
        data = {'grant_type': 'client_credentials', 'scope': scope}
        res = requests.post(url=token_url, data=data, auth=HTTPBasicAuth(client_id, client_secret))
        response = res.json()
        access_token = response['access_token']
        url = 'https://americas.discovery.api.oclc.org/worldcat/search/v2/bibs?q=bn%3A%20' + isbn

        headers = {
            "Authorization": "Bearer " + access_token
        }

        r = requests.get(url, headers=headers)
        res = r.json()
        try:
            desc = res['bibRecords'][0]['description']['summaries'][0]['text']
        except Exception as e:
            if e == "string indices must be integers":
                desc = res['bibRecords'][0]['description']['summaries']['text']
            else:
                desc = ""

        try:
            bk_format = res['bibRecords'][0]['format']['materialTypes']
        except Exception as e:
            if e == "string indices must be integers":
                bk_format = res['bibRecords'][0]['format']
            else:
                bk_format = ""
        try:
            phys_desc = res['bibRecords'][0]['description']['physicalDescription']
        except Exception as e:
            if e == "string indices must be integers":
                phys_desc = res['bibRecords'][0]['description']
            else:
                phys_desc = ""

        try:
            genres = res['bibRecords'][0]['description']['genres']
        except Exception as e:
            if e == "string indices must be integers":
                genres = res['bibRecords'][0]['description']
            else:
                genres = "None"

        book_dict = {
            "title": res['bibRecords'][0]['title']['mainTitles'][0]['text'],
            "author": res['bibRecords'][0]['contributor']['statementOfResponsibility']['text'],
            "desc": desc,
            "subject": res['bibRecords'][0]['subjects'],
            "bk_format": bk_format,
            "phys_desc": phys_desc,
            "genres": genres
        }
        return book_dict
    
    except Exception as e:
        return f"An Error Occured oclc: {e}"


def images(isbn):
    try:
        url = "https://www.googleapis.com/books/v1/volumes?q=isbn:" + isbn + "&key=" + key + "&fields=kind,items(volumeInfo(imageLinks))"
        response = requests.get(url)

        json_data = json.loads(response.text)
        imgurl = "test"
        if 'items' in json_data.keys():
            if 'volumeInfo' in json_data['items'][0].keys():
                if 'imageLinks' in json_data['items'][0]['volumeInfo'].keys():
                    imgurl = json_data['items'][0]['volumeInfo']['imageLinks']['smallThumbnail']
        if imgurl == "test":
            imgurl = "null"
        return imgurl

    except Exception as e:
        return f"An Error Occured: {e}"


@app.route('/add', methods=['POST', 'GET'])
@firebase.jwt_required
def create():
    if request.method == 'POST':
        try:
            auth_head = request.headers.get('Authorization')
            curr_id_token = auth_head[7:]
            decoded_token = auth.verify_id_token(curr_id_token)
            uid = decoded_token['uid']
            rec_id = request.json['id']
            request.json['user'] = uid
            book_dict = oclc2(request.json['isbn'])
            request.json['isbn'] = request.json['isbn'].replace('-', '')
            img = images(request.json['isbn'])
            ind = book_dict['title'].index("/")
            trunc_title = book_dict['title'][0:ind]
            request.json['title'] = trunc_title
            request.json['author'] = book_dict['author']
            request.json['desc'] = book_dict['desc']
            request.json['subject'] = book_dict['subject']
            request.json['bk_format'] = book_dict['bk_format']
            request.json['phys_desc'] = book_dict['phys_desc']
            request.json['genre'] = book_dict['genres']
            request.json['img'] = img

            book_ref.document(rec_id).set(request.json)

            return jsonify({"success": True,
                            "curr_id_token": curr_id_token,
                            }), 200
        except Exception as e:
            return f"An Error Occured post: {e}"
    else:
        return jsonify({"success": True})


@app.route('/list', methods=['GET'])
@firebase.jwt_required
def read():
    try:
        auth_head = request.headers.get('Authorization')
        curr_id_token = auth_head[7:]
        decoded_token = auth.verify_id_token(curr_id_token)
        uid = decoded_token['uid']
        if uid:
            query_ref = book_ref.where(u'user', u'==', uid)
            user_books = [doc.to_dict() for doc in query_ref.stream()]
            response = jsonify(user_books)
            return response
        else:
            all_books = [doc.to_dict() for doc in book_ref.stream()]
            response = jsonify(all_books)
            return response
    except Exception as e:
        return f"An Error Occured: {e}"


@app.route('/title', methods=['GET'])
@firebase.jwt_required
def read_book():
    try:
        get_id = request.args.get('book_id')
        auth_head = request.headers.get('Authorization')
        curr_id_token = auth_head[7:]
        decoded_token = auth.verify_id_token(curr_id_token)
        uid = decoded_token['uid']
        if uid:
            query_ref = book_ref.where(u'user', u'==', uid)
            user_books = [doc.to_dict() for doc in query_ref.stream()]
            user_books_id = [book_dict for book_dict in user_books if book_dict['id'] == get_id]
            response = jsonify(user_books_id)
            return response
        else:
            all_books = [doc.to_dict() for doc in book_ref.stream()]
            response = jsonify(all_books)
            return response
    except Exception as e:
        return f"An Error Occured: {e}"


@app.route('/delete', methods=['GET', 'POST'])
def delete():
    try:
        request_data = request.get_json()
        del_id = request_data['id']
        book_ref.document(del_id).delete()
        return jsonify({"success": True})
    except Exception as e:
        return f"An Error Occured: {e}"


if __name__ == '__main__':
    app.run(threaded=True, port=5000)
