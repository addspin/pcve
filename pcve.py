import requests
import zipfile
from datetime import datetime, timedelta, timezone
import os
import sqlite3
import json
from pathlib import Path
import shutil

# Текущая дата
current_datetime  = datetime.now(timezone.utc)
download_date = current_datetime.strftime("%Y-%m-%d_%H00Z")
download_time = current_datetime.strftime("%H00Z")
download_only_date = current_datetime.strftime("%Y-%m-%d")

# Specify folder full-delta cve path and database path
folder_path_full = f"tmp_full/cvelistV5-cve_{download_date}/cves/2024/25xxx/"
folder_path_delta = f"tmp_delta/{download_only_date}_delta_CVEs_at_{download_time}/deltaCves/"
db_path = "db/pcve.db"

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
        
    # add JSON files in db BLOB
    # if not os.path.exists('tmp_full/install_complete'):
    add_full_cve_json_files(folder_path_full, db_path)

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
    add_delta_cve_json_files(folder_path_delta, db_path)
        
    # Удаление ненужных файлов
    os.remove(f"tmp_delta/tmp_delta.zip")
    shutil.rmtree(f'tmp_delta/{download_only_date}_delta_CVEs_at_{download_time}')
    with open(f'tmp_full/install_complete', 'w'):
        pass

def add_full_cve_json_files(folder_path_full, db_path):
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
    for filename in os.listdir(folder_path_full):
        filepath = os.path.join(folder_path_full, filename)
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
            print(f"CVE record with ID {cveId} inserted successfully.")

    # Close connection
    conn.close()

def add_delta_cve_json_files(folder_path_delta, db_path):
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
            print(f"CVE record with ID {cveId} inserted successfully.")

    # Close connection
    conn.close()

## if not install - INIT!
if not os.path.isdir("tmp_full") or not os.listdir("tmp_full"): 
    download_full_cve()

# # Specify folder path and database path
# folder_path = f"tmp_full/cvelistV5-cve_{download_date}/cves/2024/25xxx/"
# db_path = "db/pcve.db"

# # add JSON files in db BLOB
# if not os.path.exists('tmp_full/install_complete'):
#     add_json_files(folder_path, db_path)

conn = sqlite3.connect(db_path)
c = conn.cursor()

cveId = "CVE-2024-25100"

blob_data = c.execute("SELECT jsonData FROM cve WHERE cveId = ?", (cveId,)).fetchone()[0]

json_data = json.loads(blob_data)

cve_id = json_data['cveMetadata']['cveId']
print(f"CVE ID: {cve_id}")

descriptions = json_data['containers']['cna']['descriptions']
descriptions_values = [description["value"] for description in descriptions]
first_description_value = descriptions_values[0]
print(f"Description: {first_description_value}")

if "exploits" in json_data["containers"]["cna"]:
    exploits_values = json_data["containers"]["cna"]["exploits"]
    first_exploits_value = exploits_values[0]
    print(f"exploits: {first_exploits_value}")


affecteds = json_data['containers']['cna']['affected']
affecteds_values = [affected["product"] for affected in affecteds]
product_affecteds_value = affecteds_values[0]
print(f"Product: {product_affecteds_value}")

affecteds_values = [affected["vendor"] for affected in affecteds]
vendor_affecteds_value = affecteds_values[0]
print(f"Vendor: {vendor_affecteds_value}")

metrics = json_data['containers']['cna']['metrics']
metrics_values = [metric["cvssV3_1"] for metric in metrics]
cvssV3_1_metrics_value = metrics_values[0]
version_metrics_value = cvssV3_1_metrics_value["version"]
attackVector_metrics_value = cvssV3_1_metrics_value["attackVector"]
attackComplexity_metrics_value = cvssV3_1_metrics_value["attackComplexity"]
baseSeverity_metrics_value = cvssV3_1_metrics_value["baseSeverity"]
print(f"CVSS version: {version_metrics_value}")
print(f"attackVector: {attackVector_metrics_value}")
print(f"attackComplexity: {attackComplexity_metrics_value}")
print(f"LVL: {baseSeverity_metrics_value}")






conn.close()
