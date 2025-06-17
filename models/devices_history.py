from datetime import datetime
from flask import jsonify
from flask_jwt_extended import get_jwt_identity

class DevicesHistory:
    def __init__(self, db):
        self.collection = db['history_devices']

    def save_history(self, data):
        user_id = get_jwt_identity()

        device_name = data.get('device_name')
        device_os = data.get('device_os')
        device_id = data.get('device_id')
        login_time = datetime.utcnow()

        if not all([device_name, device_os, device_id]):
            return jsonify({
                'status': 'error',
                'message': 'Missing device information',
                'data': None
            }), 400

        try:
            self.collection.insert_one({
                'user_id': user_id,
                'device_name': device_name,
                'device_os': device_os,
                'device_id': device_id,
                'login_time': login_time
            })
            return jsonify({
                'status': 'success',
                'message': 'Device history saved',
                'data': None
            }), 201
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e),
                'data': None
            }), 500

    def get_user_history(self):
        user_id = get_jwt_identity()

        try:
            history = list(self.collection.find({'user_id': user_id}))
            for item in history:
                item['_id'] = str(item['_id'])
                item['login_time'] = item['login_time'].strftime("%Y-%m-%d %H:%M:%S")

            return jsonify({
                'status': 'success',
                'message': 'Device history fetched',
                'data': history
            }), 200
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e),
                'data': None
            }), 500
