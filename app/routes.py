import io
from urllib import response
from flask import Flask, request, jsonify, make_response, Response
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import jwt
import datetime
import csv
from functools import wraps
from app import app, db
from app.models import Card, Score, User

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['username'] = user.username
        user_data['name'] = user.name
        user_data['email'] = user.email
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    response = jsonify({'users' : output})
    return response

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

@app.route('/admin', methods=['POST'])
def create_admin():

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), username=data['username'],  email=data['email'], name=data['name'], password=hashed_password, admin=True)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'Admin created!'})

@app.route('/register', methods=['POST'])
def register_user():

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), username=data['username'],  email=data['email'], name=data['name'],password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    response  = jsonify({'message' : 'New user created!'})
    return response

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), username=data['username'],  email=data['email'], name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New user created!'})

@app.route('/currentuser', methods=['GET'])
@token_required
def get_user(current_user):
    
    user_data = {}
    user_data['id'] = current_user.id
    user_data['public_id'] = current_user.public_id
    user_data['username'] = current_user.username
    user_data['email'] = current_user.email
    user_data['name'] = current_user.name
    response = jsonify(user_data)
    return response

@app.route('/currentuser', methods=['PUT'])
@token_required
def update_user(current_user):

    data = request.get_json()
    print(data, current_user.public_id)

    user = User.query.filter_by(public_id=current_user.public_id).first()

    user.email = data["email"]
    user.name = data["name"]
    
    db.session.commit()

    response = jsonify({'message' : 'The user has been updated!'})
    return response

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user has been promoted!'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted!'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    response = None
    if not username or not password:
        response = make_response('Could not verify, Incorrect username or password', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(username=username).first()

    if not user:
        response = make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=120)}, app.config['SECRET_KEY'])

        response = jsonify({'token' : token.decode('UTF-8')})

    return response

@app.route('/card', methods=['GET'])
@token_required
def get_all_cards(current_user):
    cards = Card.query.filter_by(user_id=current_user.id).all()

    output = []

    for card in cards:
        card_data = {}
        card_data['id'] = card.id
        card_data['topic'] = card.topic
        card_data['question'] = card.question
        card_data['answer'] = card.answer
        card_data['timestamp'] = card.timestamp
        output.append(card_data)

    response = jsonify({'cards' : output})
    return response

@app.route('/card/download', methods=['GET'])
@token_required
def downloads_cards(current_user):
    cards = Card.query.filter_by(user_id=current_user.id).all()
    output = io.StringIO()
    writer = csv.writer(output)
		
    line = ['topic, question, answer, timestamp, score, attempts']
    writer.writerow(line)

    for card in cards:
        score = Score.query.filter_by(card_id=card.id).first()
        line = [str(card.topic) + ',' + str(card.question) + ',' + str(card.answer) + ','+ str(card.timestamp) + ',' + str(score.score) + ',' + str(score.attempts)]
        writer.writerow(line)

    output.seek(0)
		
    return Response(output, mimetype="text/csv", headers={"Content-Disposition":"attachment;filename=flash_card_report.csv"})

@app.route('/card/data', methods=['GET'])
@token_required
def cards_data(current_user):
    cards = Card.query.filter_by(user_id=current_user.id).all()
		
    output = []

    for card in cards:
        score = Score.query.filter_by(card_id=card.id).first()
        output.append({'id': str(card.id), 'topic': str(card.topic), 'question': str(card.question), 'answer': str(card.answer), 'timestamp': str(card.timestamp), 'score': str(score.score),'attempts': str(score.attempts)})
		
    return jsonify(output)

@app.route('/card/<card_id>', methods=['GET'])
@token_required
def get_one_card(current_user, card_id):
    card = Card.query.filter_by(id=card_id, user_id=current_user.id).first()

    if not card:
        return jsonify({'message' : 'No card found!'})

    card_data = {}
    card_data['id'] = card.id
    card_data['topic'] = card.topic
    card_data['question'] = card.question
    card_data['answer'] = card.answer
    card_data['timestamp'] = card.timestamp

    response = jsonify(card_data)
    return response

@app.route('/card', methods=['POST'])
@token_required
def create_card(current_user):
    data = request.get_json()
    new_card = Card(topic=data['topic'], question=data['question'], answer=data['answer'], user_id=current_user.id)
    db.session.add(new_card)
    db.session.commit()
    create_score(current_user, new_card.id)

    return jsonify({'message' : "Card created!"})

@app.route('/card/<card_id>', methods=['PUT'])
@token_required
def update_card(current_user, card_id):
    data = request.get_json()
    card = Card.query.get(card_id)
    card.question = data["question"]
    card.answer = data["answer"]
    card.topic = data["topic"]
    
    db.session.commit()

    return jsonify({'message' : 'Card has been updated!'})

@app.route('/card/<card_id>', methods=['DELETE'])
@token_required
def delete_card(current_user, card_id):
    card = Card.query.filter_by(id=card_id, user_id=current_user.id).first()
    score = Score.query.filter_by(card_id=card_id, user_id=current_user.id).first()
    if not card:
        return jsonify({'message' : 'No card found!'})

    db.session.delete(card)
    db.session.delete(score)
    db.session.commit()

    return jsonify({'message' : 'Card deleted!'})

@app.route('/totalscore', methods=['GET'])
@token_required
def get_total_score(current_user):
    scores = Score.query.filter_by(user_id=current_user.id).all()

    total_score = total_attempts = 0

    for score in scores:
        total_score += score.score
        total_attempts += score.attempts

    return jsonify({'total_score' : total_score, 'total_attempts': total_attempts})

@app.route('/score/<card_id>', methods=['GET'])
@token_required
def get_score_of_card(current_user, card_id):
    score = Score.query.filter_by(card_id=card_id, user_id=current_user.id).first()

    if not score:
        return jsonify({'message' : 'No card found!'})

    
    return jsonify({'score' : score.score})

# @app.route('/score/<card_id>', methods=['POST'])
# @token_required
def create_score(current_user, card_id):
    new_score = Score(score=0, attempts=0, card_id=card_id, user_id=current_user.id)
    db.session.add(new_score)
    db.session.commit()

    return jsonify({'message' : "Score created!"})

@app.route('/score/increment/<card_id>', methods=['PUT'])
@token_required
def increment_score(current_user, card_id):
    score = Score.query.filter_by(card_id=card_id, user_id=current_user.id).first()

    if not score:
        return jsonify({'message' : 'No score found!'})

    score.score += 1
    score.attempts += 1
    db.session.commit()

    return jsonify({'message' : 'Score/Attempts Incremented!'})

@app.route('/attempts/increment/<card_id>', methods=['PUT'])
@token_required
def increment_attempts(current_user, card_id):
    score = Score.query.filter_by(card_id=card_id, user_id=current_user.id).first()

    if not score:
        return jsonify({'message' : 'No card found!'})

    score.attempts += 1
    db.session.commit()

    return jsonify({'message' : 'Attempts Incremented!'})

@app.route('/score/<card_id>', methods=['DELETE'])
@token_required
def delete_score(current_user, card_id):
    score = Score.query.filter_by(card_id=card_id, user_id=current_user.id).first()

    if not score:
        return jsonify({'message' : 'No score found!'})

    db.session.delete(score)
    db.session.commit()

    return jsonify({'message' : 'Score item deleted!'})

@app.route('/score', methods=['DELETE'])
@token_required
def delete_all_score(current_user):
    score = Score.query.filter_by(user_id=current_user.id).first()

    if not score:
        return jsonify({'message' : 'No score found!'})

    db.session.delete(score)
    db.session.commit()

    return jsonify({'message' : 'Scores item deleted!'})