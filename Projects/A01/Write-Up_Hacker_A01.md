# Отчет об анализе защищенности

 - Целевая система: **Simple Backend JAVA (Backend_JAVA_A01_v1)**
 - Классификация обнаруженных угроз: **OWASP Top 10 - A01:2021 (BOLA: IDOR)**

----

# DAST Анализ

## №1: Разведка

В следствии разведки и ознакомлении с отчетом Разработчика было выявлено:

 - На сайте имеется такие эндпоинты:
     - `/api/profile` - профиль пользователя
     - `/api/users/list` - список пользователей

Переход по эндпоинту `GET /api/users/list` выдало список пользователей, которые имеют, по мимо общей сводки информации, уникальный ID

<img width="225" height="321" alt="{2FE79AF0-BE7B-4D1F-AB70-E5076D83D6A0}" src="https://github.com/user-attachments/assets/9d3a4509-8df1-4bfd-bec2-bdab6bc0cc81" />

## №2: Уязвимость IDOR

Протестируем сайт на уязвимость **IDOR**

<details>
<summary><b>Что такое IDOR?</b></summary>

> **IDOR (Insecure Direct Object Reference)** — это уязвимость, которая возникает, когда приложение предоставляет прямой доступ к объектам (файлам, аккаунтам, записям в БД) по их идентификаторам без проверки прав доступа. Злоумышленник может изменить ID в запросе (например, с 123 на 124) и получить доступ к чужим данным.

</details>


После нахождения ID каждого пользователя в базе, учитывая **admin**, перейдем по эндпоинту `GET /api/profile`.

Разработчиком было указано как используется в данном эндопинте ID, а именно в самом запросе - вводим `GET /api/profile?id=1`

<img width="371" height="174" alt="{FFCD92B3-B311-4B74-873F-867AED7256D6}" src="https://github.com/user-attachments/assets/991fa24c-9ddb-4725-b1b4-95a6a770d1de" />

## №3: Результат

После эксплуатации уязвимости **IDOR** нам показало, будучи не зарегестрированным пользователем, информацию другого человека

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

Структура имеет стандартный вид чистого backend с файлом **UserController.java**, отвечающая за логику работы. Ничего подозрительного из списка. Перейдем к анализу кода

## №2: Анализ исходного кода

В файле **UserController.java** представлена логика работы эндпоинтов:
```java
@RestController
public class UserController {
    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    @GetMapping("/api/profile")
    public Map<String, Object> getProfile(@RequestParam String id) {
        String sql = "SELECT username, secret_note FROM users WHERE id = " + id;
        return jdbcTemplate.queryForMap(sql);
    }
    
    @GetMapping("/api/users/list")
    public List<Map<String, Object>> listUsers() {
        return jdbcTemplate.queryForList("SELECT id, username FROM users");
    }
}
```
Исходя из структуры замечаем недостаток - Никакой из эндпоинтов не проверяет сессии, пренадлежности тех или иных данных, и регистрации/входа.

Для дальнейшей работы данный блок кода оставлять **нельзя**, даже при условии добавления регистрации/входа

## №3: Главная проблема

Из за отсутсвия валидации пренадлежности и регистрации с входом появляется риск утечки крит. информации через уязвимость **IDOR (Insecure Direct Object Reference)**

Вставляя в параметр `?id=` на эндпоинте `/api/profile`, ID проходит через SQL запрос, без проверки сессии отправителя, и выдает информацию о данном ID.

## №4: Рекомендации по исправлению

- Добавить регистрацию/вход
- Добавить валидацию ID. Сравнить сессию пользователя и пренадлежность данного ID.

Пример реализации регистрации/вход:

### Регистрация: 

```java
@PostMapping("/api/auth/register")
    public ResponseEntity<String> register(@RequestBody Map<String, String> payload) {
        String username = payload.get("username");
        String password = payload.get("password");
        String secretNote = payload.get("secret_note");

        String sql = "INSERT INTO users (username, password, secret_note) VALUES (?, ?, ?)";
        jdbcTemplate.update(sql, username, password, secretNote);

        return ResponseEntity.ok("User registered successfully");
    }
```

 - В **/api/auth/register/** принимается запрос с JSON телом, с параметрами `username`, `password`, `secret_note`, который позже записывается в базу данных

### Вход:
```java
@PostMapping("/api/auth/login")
    public ResponseEntity<String> login(@RequestBody Map<String, String> payload, HttpServletRequest request) {
        String username = payload.get("username");
        String password = payload.get("password");

        try {
            String sql = "SELECT id FROM users WHERE username = ? AND password = ?";
            Map<String, Object> user = jdbcTemplate.queryForMap(sql, username, password);
            
            HttpSession session = request.getSession(true);
            session.setAttribute("userId", user.get("id").toString());
            
            return ResponseEntity.ok("Login successful");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }
```

 - В **/api/auth/login/** принимается запрос с JSON телом, с параметрами `username`, `password`, который сверяет с базой данных на наличие этого пользователя и валидного пароля. После выдается пользователю `session` токен, который записывается в Cookie.

Данный `session` токен после этого должен сверятся на каждом эндпоинте из нынешнего блока кода в **UserController.java**

Пример проверки `session` токена:

```java
@GetMapping("/api/profile")
    public Map<String, Object> getProfile(HttpSession session) {
        Object userId = session.getAttribute("userId");
        if (userId == null) {
            throw new RuntimeException("Ошибка: Вы не авторизованы!");
        }
 // ...Логика работы эндпоинта
```

В данном примере принимается от пользователя лишь `session` токен и идет проверка авторизации пользователя. Если токена нету, либо его несуществует в базе - **"Ошибка, вы не авторизованы"**
