# pcve
parsing cve

1) Установка

 Скачиваем полный список всех CVE на текущую дату: 
 https://github.com/CVEProject/cvelistV5/archive/refs/tags/cve_2024-02-12_0700Z.zip
 Распаковываем

2) Создаем структуру базы данных со всеми полями full-record-advanced-example.json (BLOB) в sqlite 
3) Заполняем базу значеним по каждой CVE где cveId уникальный ключ, если встретится повторяющиеся значения перезаписываем

4) Скачиваем дельты
https://github.com/CVEProject/cvelistV5/releases/download/cve_2024-02-12_0800Z/2024-02-12_delta_CVEs_at_0800Z.zip
