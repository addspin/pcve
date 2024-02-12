# pcve
parsing cve

1) парсим 

 Скачиваем полный список всех CVE на текущую дату: https://github.com/CVEProject/cvelistV5/releases/download/cve_2024-02-12_0600Z/2024-02-12_all_CVEs_at_midnight.zip.zip

 https://github.com/CVEProject/cvelistV5/archive/refs/tags/cve_2024-02-12_0700Z.zip
 Распаковываем



2) Создаем структуру базы данных со всеми полями full-record-advanced-example.json в sqlite 
3) Заполняем базу значеним по каждой CVE где cveId уникальный ключ, если встретится повторяющиеся значения перезаписываем

4) 
Пишем на python бота:

1) Скачиваем архив  https://github.com/CVEProject/cvelistV5/archive/refs/tags/cve_2024-02-12_0700Z.zip

Где: cve_2024-02-12_0700Z.zip