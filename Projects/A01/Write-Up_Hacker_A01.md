# Отчет об анализе защищенности

 - Целевая система: **Simple Backend JAVA (Backend_JAVA_A01_v1)**
 - Классификация обнаруженных угроз: **OWASP Top 10 - A01:2021 (BOLA: IDOR)**

----

# DAST Анализ

## №1: Разведка

В следствии разведки и ознакомлении с отчетом Разработчика было выявлено:

 - На сайте имеется такие эндпоинты: `/api/profile` - профиль пользователя, и `/api/users/list` - список пользователей

Переход по эндпоинту `GET /api/users/list` выдало список пользователей, которые имеют, по мимо общей сводки информации, уникальный ID

<img width="225" height="321" alt="{2FE79AF0-BE7B-4D1F-AB70-E5076D83D6A0}" src="https://github.com/user-attachments/assets/9d3a4509-8df1-4bfd-bec2-bdab6bc0cc81" />

## №2: Уязвимость IDOR

После нахождения ID каждого пользователя в базе, учитывая **admin**, перейдем по эндпоинту `GET /api/profile`.

Разработчиком было указано как используется в данном эндопинте ID, а именно в самом запросе - вводим `GET /api/profile?id=1`

<img width="371" height="174" alt="{FFCD92B3-B311-4B74-873F-867AED7256D6}" src="https://github.com/user-attachments/assets/991fa24c-9ddb-4725-b1b4-95a6a770d1de" />

## №3: Результат

После эксплуатации уязвимости IDOR нам показало, будучи не зарегестрированным пользователем, информацию другого человека

------

### **Флаг найден:** FLAG{ID0R_D3T3ct3d}

------

# SAST Анализ

## №1: Анализ структуры проекта

```text
Backend_JAVA_A01_v1/
├── src/
│   ├── main/
│   │   ├── java/com/idortest/vulnerableapi/
│   │   │   ├── UserController.java
│   │   │   └── VulnerableApiApplication.java
│   │   └── resources/
│   │       ├── application.properties
│   │       └── schema.sql
│   └── test/java/com/idortest/vulnerableapi/
│       └── VulnerableApiApplicationTests.java
├── HELP.md
├── mvnw
├── mvnw.cmd
└── pom.xml
```

Структура имеет стандартный вид чистого backend. Ничего подозрительного из списка. Перейдем к анализу логики кода

## №2: Анализ исходного кода



## №3: Главная проблема

## №4: Рекомендации по исправлению

- Добавить регистрацию/вход
- Добавить валидацию ID. Сравнить сессию пользователя и пренадлежность данного ID.
