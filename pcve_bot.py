import requests
import zipfile
from datetime import datetime, timedelta, timezone
import os
import sqlite3
import json
from pathlib import Path
import shutil
# import redis

import telegram
import aiogram
import asyncio
from celery import Celery


from flask import Flask, request

app = Flask(__name__)

bot = aiogram.Bot(token='6379047592:AAGF_dv5GUOry9vDph03-bNAWdbpFQR4AJI')
group_id = '-4142947007'
channel_id = '-1002009744461'

@app.route('/webhook', methods=['POST'])
def webhook():
    # Обработать запрос от Telegram
    update = request.get_json()

    # ...

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

    add action=dst-nat chain=dstnat dst-port=443 in-interface-list=WAN protocol=tcp to-addresses=10.13.1.80 to-ports=8080