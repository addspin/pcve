import requests
import zipfile
from datetime import datetime, timedelta, timezone
import os
import sqlite3
import json
from pathlib import Path
import shutil

import telegram
import aiogram
import asyncio
import config

bot = aiogram.Bot(token=config.token)
group_id = config.group_id
channel_id = config.channel_id

# Текущая дата
current_datetime  = datetime.now(timezone.utc)
download_date = current_datetime.strftime("%Y-%m-%d_%H00Z")
download_time = current_datetime.strftime("%H00Z")
download_only_date = current_datetime.strftime("%Y-%m-%d")

# Specify folder full-delta cve path and database path
folder_path_full = f"tmp_full/cvelistV5-cve_{download_date}/cves/"
folder_path_delta = f"tmp_delta/deltaCves/"
db_path = "db/pcve.db"


message_count = 0
max_messages = 19

async def send_cve_to_telegram(cveId):
    global message_count
    if message_count >= max_messages:
        await asyncio.sleep(300)  # Пауза на 1 минуту
        message_count = 0
    message_count += 1
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    blob_data = c.execute("SELECT jsonData FROM cve WHERE cveId = ?", (cveId,)).fetchone()[0]

    json_data = json.loads(blob_data)

    cve_id = json_data['cveMetadata']['cveId']

    first_description_value = " "

    if "descriptions" in json_data["containers"]["cna"]:
        descriptions = json_data['containers']['cna']['descriptions']
        descriptions_values = [description["value"] for description in descriptions]
        first_description_value = descriptions_values[0]
        # print(f"Description: ---- {first_description_value}")

    exploits = " "
    if "exploits" in json_data["containers"]["cna"]:
        exploits_values = json_data["containers"]["cna"]["exploits"]
        first_exploits_value = exploits_values[0]
        exploits = first_exploits_value.get("value", " ")


    affecteds = " "
    product_affecteds_value = " "
    vendor_affecteds_value = " "

    if "affected" in json_data["containers"]["cna"]:
        affecteds = json_data['containers']['cna']['affected']
        affecteds_values = [affected["product"] for affected in affecteds]
        product_affecteds_value = affecteds_values[0]
        # print(f"Product: {product_affecteds_value}")

        affecteds_values = [affected["vendor"] for affected in affecteds]
        vendor_affecteds_value = affecteds_values[0]
        # print(f"Vendor: {vendor_affecteds_value}")

    version = " "
    attackVector = " "
    attackComplexity = " "
    baseSeverity =  " "

    if "metrics" in json_data["containers"]["cna"]:
        metrics = json_data['containers']['cna']['metrics']
        # print("TEST metrics ---", metrics)
        cvssV3_1_metrics_value = metrics[0]
        version = cvssV3_1_metrics_value.get("cvssV3_1", {}).get("version", " ")
        attackVector = cvssV3_1_metrics_value.get("cvssV3_1", {}).get("attackVector", " ")
        attackComplexity = cvssV3_1_metrics_value.get("cvssV3_1", {}).get("attackComplexity", " ")
        baseSeverity = cvssV3_1_metrics_value.get("cvssV3_1", {}).get("baseSeverity", " ")

    conn.close()

    message = f'''Новые CVE на {download_date}:\n
<b>CVE ID:</b> {cve_id}
<b>CVSS version:</b> {version}
<b>LVL:</b> {baseSeverity}
<b>Product:</b> {product_affecteds_value}
<b>Vendor:</b> {vendor_affecteds_value}
<b>Attack Vector:</b> {attackVector}
<b>Attack Complexity:</b> {attackComplexity}
<b>Exploits:</b> {exploits}\n
<b>Description:</b> {first_description_value}\n'''
    if any(c != " " for c in [version, baseSeverity, product_affecteds_value, vendor_affecteds_value, attackVector, attackComplexity, exploits, first_description_value]):
        try:
            await bot.send_message(chat_id=group_id, text=message, parse_mode="HTML")
        except Exception as e:
            print(f"Ошибка при отправке сообщения: {e}")

def download_full_cve():
    # URL-адрес архива
    url = f"https://github.com/CVEProject/cvelistV5/archive/refs/tags/cve_{download_date}.zip"

    # Скачивание архива
    response = requests.get(url)

    # Сохранение архива
    with open("tmp_full/tmp_full.zip", "wb") as f:
        f.write(response.content)

    # Распаковка архива
    with zipfile.ZipFile("tmp_full/tmp_full.zip", "r") as zip_ref:
        zip_ref.extractall("tmp_full")
        
    os.remove(f"tmp_full/cvelistV5-cve_{download_date}/cves/delta.json")
    os.remove(f"tmp_full/cvelistV5-cve_{download_date}/cves/deltaLog.json")
    
    # recursive search file for add JSON files in db BLOB
    list_files(folder_path_full)

    # Удаление ненужных файлов
    os.remove(f"tmp_full/tmp_full.zip")
    shutil.rmtree(f'tmp_full/cvelistV5-cve_{download_date}')
    with open(f'tmp_full/install_complete', 'w'):
        pass

def download_delta_cve():
    # URL-адрес архива
    url = f"https://github.com/CVEProject/cvelistV5/releases/download/cve_{download_date}/{download_only_date}_delta_CVEs_at_{download_time}.zip"

   
    # Скачивание архива
    response = requests.get(url)

    # Сохранение архива
    with open("tmp_delta/tmp_delta.zip", "wb") as f:
        f.write(response.content)

    # Распаковка архива
    with zipfile.ZipFile("tmp_delta/tmp_delta.zip", "r") as zip_ref:
        zip_ref.extractall("tmp_delta")
    
    # add delta JSON files in db BLOB
    async def add_delta():
        await add_delta_cve_json_files(folder_path_delta, db_path)
    asyncio.run(add_delta())
        # app.start()

    # Удаление ненужных файлов
    os.remove(f"tmp_delta/tmp_delta.zip")
    shutil.rmtree(f'{folder_path_delta}')
    
def list_files(folder_path_full):
      for filename in os.listdir(folder_path_full):
        filepath = os.path.join(folder_path_full, filename)
        if os.path.isfile(filepath):
            with open(filepath, 'r') as f:
                json_data = json.load(f)
                add_full_cve_json_files(json_data)
        elif os.path.isdir(filepath):
            list_files(filepath)

count = 0
# add JSON files in db BLOB
def add_full_cve_json_files(json_data):
    # Connect to database
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Create table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS cve (
        cveId TEXT PRIMARY KEY NOT NULL UNIQUE,
        jsonData BLOB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    cveId = json_data['cveMetadata']['cveId']

    # Check for existing entry
    existing_entry = c.execute("SELECT * FROM cve WHERE cveId = ?", (cveId,)).fetchone()

    if existing_entry:
        c.execute("""UPDATE cve SET jsonData = ?
                            WHERE cveId = ?""", (json.dumps(json_data), cveId))
        conn.commit()
    else:
        # Insert new record
        c.execute("""INSERT INTO cve (cveId, jsonData)
                        VALUES (?, ?)""", (cveId, json.dumps(json_data)))
        conn.commit()
        global count
        count += 1
        print(f"CVE record with ID {cveId} inserted successfully. {count}")
    # Close connection
    conn.close()
   
count = 0
async def add_delta_cve_json_files(folder_path_delta, db_path):
    
    # Connect to database
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Create table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS cve (
        cveId TEXT PRIMARY KEY NOT NULL UNIQUE,
        jsonData BLOB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # Iterate through JSON files
    for filename in os.listdir(folder_path_delta):
        filepath = os.path.join(folder_path_delta, filename)
        with open(filepath, 'r') as f:
            json_data = json.load(f)

        cveId = json_data['cveMetadata']['cveId']

        # Check for existing entry
        existing_entry = c.execute("SELECT * FROM cve WHERE cveId = ?", (cveId,)).fetchone()

        if existing_entry:
            c.execute("""UPDATE cve SET jsonData = ?
                             WHERE cveId = ?""", (json.dumps(json_data), cveId))
            conn.commit()
        else:
            # Insert new record
            c.execute("""INSERT INTO cve (cveId, jsonData)
                         VALUES (?, ?)""", (cveId, json.dumps(json_data)))
            conn.commit()
            global count
            count += 1
            print(f"CVE record with ID {cveId} inserted successfully. {count}")
            # print("КАКОЙ CVE---", cveId)
            await send_cve_to_telegram(cveId)
        
    # Close connection
    conn.close()

## if not install - INIT!
if not os.path.isdir("tmp_full") or not os.listdir("tmp_full"): 
    download_full_cve()
    list_files(folder_path_full)

download_delta_cve()





