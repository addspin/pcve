import requests
import zipfile
from datetime import datetime, timedelta, timezone
import os
import sqlite3
import json


# Текущая дата
current_datetime  = datetime.now(timezone.utc)
download_date = current_datetime.strftime("%Y-%m-%d_%H00Z")

if not os.path.isdir("tmp_full") or not os.listdir("tmp_full"): 
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

    # Удаление ненужных файлов
    os.remove(f"tmp_full/cvelistV5-{download_date}/cves/deltaLog.json")
    os.remove(f"tmp_full/cvelistV5-{download_date}/cves/delta.json")
    os.remove(f"tmp_full/cvelistV5-{download_date}/cves/tmp_full.zip")
else:
    print("Папка не пустая!")

def process_json_files(folder_path, db_path):
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
    for filename in os.listdir(folder_path):
        filepath = os.path.join(folder_path, filename)
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


# Specify folder path and database path
folder_path = "tmp_full/cvelistV5-cve_2024-02-12_0900Z/cves/2024/25xxx/"
db_path = "db/pcve.db"
# Process JSON files
# process_json_files(folder_path, db_path)
conn = sqlite3.connect(db_path)
c = conn.cursor()

cveId = "CVE-2024-25100"

blob_data = c.execute("SELECT jsonData FROM cve WHERE cveId = ?", (cveId,)).fetchone()[0]

json_data = json.loads(blob_data)

cve_id = json_data['cveMetadata']['cveId']
descriptions = json_data['containers']['cna']['descriptions']
descriptions_values = [description["value"] for description in descriptions]
first_description_value = descriptions_values[0]

# affected = json_data['containers']['cna']['affected']
# affected_values = [affected["productt"] for affected in affected]

# product_affected_values = affected_values[0]

# print(f"Product: {product_affected_values}")


affected = json_data['containers']['cna']['affected']
affected_values = [affected["product"] for affected in affected]
product_affected_values = affected_values[0]
# Проверка существования ключа "product"
if "product" in affected["product"]:
    # Извлечение значения "product"
    product_value = affected["product"]

    # Удаление лишних пробелов (опционально)
    # product_value = product_value.strip()

    # Проверка на пустое значение
    if product_value:
        print(f"Product: {product_value}")
    else:
        print("Product key exists, but the value is empty.")
else:
    print("Product key does not exist.")




print(f"CVE ID: {cve_id}")
print(f"Description: {first_description_value}")

# print(f"Product: {produc}")

conn.close()
