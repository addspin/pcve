# pcve
parsing cve

1) Установка

 Скачиваем полный список всех CVE на текущую дату: 
 https://github.com/CVEProject/cvelistV5/archive/refs/tags/cve_2024-02-12_0700Z.zip
 Распаковываем

2) Создаем структуру базы данных со всеми полями full-record-advanced-example.json (BLOB) в sqlite 
3) Заполняем базу значеним по каждой CVE где cveId уникальный ключ, если встретится повторяющиеся значения перезаписываем

4) 
