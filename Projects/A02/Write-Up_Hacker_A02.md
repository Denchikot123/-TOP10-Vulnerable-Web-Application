# Отчет об анализе защищенности

 - Целевая система: **Simple Backend JAVA (Backend_JAVA_A02_v1)**
 - Классификация обнаруженных угроз: **OWASP Top 10 - A02:2021 (Cryptographic Failures)**

----

# [1] DAST Анализ

## №1 Этап разведки:

Прочитав внимательно [отчет](./Write-Up_Developer_A02.md) Разработчика, можно выявить несколько изменений в проекте:

 - Добавлены токены для валидации принадлежности ID у зарегестрированного пользователя, что означает исправление уязвимости IDOR
 - Добавление регистрации и входа
 - Убраны лишние эндпоинты

Для полной "картины" проекта был запущен фаззинг и появились неупомянутые разработчиком эндпоинты: `/backup/dump.sql` и `/h2-console`

Проект не требовал регистрации/входа в эти эндпоинты

## №2 Этап ручного анализа:

Попробуем перейти в данные эндпоинты и узнать их содержание:

<img width="801" height="113" alt="изображение" src="https://github.com/user-attachments/assets/f28e40ad-216e-4476-84f6-e9bb3e43413d" />

Нам автоматически скачался какой то дамп базы данных. Как оказалось, это был вероятно забытый разработчиком дамп базы данных проекта, в котором в чистом виде передавались данные от пользователях, а именно их username и password

<img width="239" height="47" alt="изображение" src="https://github.com/user-attachments/assets/e3b284e9-a162-471c-82aa-257b2e9e3eb0" />

**Данные админа:**
 - **Username**: admin
 - **Password**: adminSUPER321

Использовав эти данные для входа в аккаунт нам выдали токен админа и показали данные этого профиля

<img width="566" height="78" alt="изображение" src="https://github.com/user-attachments/assets/845b1644-57a7-474d-89ec-93f8cd768d1d" />

## Флаг получен - FLAG{p1a1nt3xt_d0nt_do_th1s_483}

---

# [2] SAST Анализ

## №1 Анализ структуры проекта:
```text
.
└── src
    ├── main
    │   ├── java/com/idortest/vulnerableapi/
    │   │   ├── UserController.java
    │   │   └── VulnerableApiApplication.java
    │   └── resources/
    │       ├── static/backup/
    │       │   └── dump.sql
    │       ├── application.properties
    │       └── schema.sql
    └── test/java/com/idortest/vulnerableapi/
        └── VulnerableApiApplicationTests.java
```

Исходя по структуре проекта стало понятно, что делался бэкап базы SQL в файле ```dump.sql``` и отнесен в ```static/backup```, что является грубым нарушением и непониманием работы статической директории.

Но давайте поймем в чем причина передачи дампа в **чистом** виде.

## №1 Анализ логики кода:

#### UserController.java
```java
...
    @PostMapping("/api/auth/login")
    public String login(@RequestBody Map<String, String> request, HttpSession session) {
        String username = request.get("username");
        String password = request.get("password");

        String sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        
        try {
            Map<String, Object> user = jdbcTemplate.queryForMap(sql);

            session.setAttribute("userId", user.get("id"));
            session.setAttribute("username", user.get("username"));

            return "Добро пожаловать, " + user.get("username");
        } catch (Exception e) {
            return "Ошибка: Неверный логин или пароль";
        } 
    }

    @PostMapping("/api/auth/register")
    public String register(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");
        String secretNote = request.get("secret_note");

        String sql = "INSERT INTO users (username, password, secret_note) VALUES (?, ?, ?)";
        jdbcTemplate.update(sql, username, password, secretNote);

        return "Пользователь зарегистрирован!";
    }
```

Было взято 2 блока кода: **Логина** и **Регистрации**. Тут раскрывается полная картина логики работы кода

---

### 1. /api/auth/login 

Суть данного блока:

- Принимаются входные данные JSON с параметрами **username** и **password**
- Данные проходят через базу SQL H2

#### Если данные нашлись:

- Выдается session ID пользователя и выдается доступ к профилю

#### Если данные не нашлись:

- Возвращается ошибка "Неверный логин или пароль"

---

### 2. /api/auth/register

Суть данного блока:

- Принимаются входные данные JSON с параметрами **username**, **password** и **secret_note**
- Данные записываются в базу H2 и возвращается подтверждение регистрации

---

## №3 Главная проблема

Основная причина взлома является передача/выдача данных из базы в **чистом виде**, не использовав **хеширование** данных.

<details>
<summary><b>🔑 Что такое хеширование данных?</b></summary>
<blockquote>

**Хеширование** — это необратимое математическое преобразование входных данных произвольного объема в уникальную строку фиксированной длины.

Этот метод защищает данные пользователей: в случае утечки базы данных злоумышленники увидят только бесполезные хеши. Сама система проверяет пароль, повторно хешируя его при входе и сравнивая результат с сохраненным в БД значением. Чистые пароли нигде не хранятся.

</blockquote>
</details>

Если бы за место пароля был бы **хеш**, мы бы так просто не получили флаг

## №4 Рекомендации по защите

Для безопасности нужно использовать специализированный для хеширования паролей алгоритм **BCrypt**

Самый простой способ в современной Java-разработке - подключить стандартную библиотеку **Spring Security Crypto**

#### 🛠️ Подключение зависимости (Maven)
```xml
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-crypto</artifactId>
    <version>6.3.0</version> <!-- Используйте актуальную версию -->
</dependency>
```

#### 💻 Код для регистрации и авторизации
```java
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class SecurityService {
    // Создаем экземпляр энкодера (силу хеширования/глубину раундов можно настроить)
    private static final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    // 1. При РЕГИСТРАЦИИ (соль генерируется и встраивается в хеш автоматически)
    public static String hashPassword(String rawPassword) {
        return encoder.encode(rawPassword);
    }

    // 2. При АВТОРИЗАЦИИ (сравниваем введенный пароль с хешем из базы данных)
    public static boolean checkPassword(String rawPassword, String hashedPasswordFromDb) {
        return encoder.matches(rawPassword, hashedPasswordFromDb);
    }
}

```

#### Главные правила безопасности для Java-разработчика:
* ❌ **Никаких `String.hashCode()`**: этот метод предназначен только для `HashMap` и выдает всего 32 бита, коллизию можно подобрать за секунду.
* ❌ **Не изобретайте свою «соль» (salt)**: современные библиотеки вроде `BCryptPasswordEncoder` автоматически генерируют случайную соль для каждого пароля и сами упаковывают её в финальную строку хеша.
* ❌ **Не храните пароли в типе `String`**: для максимальной безопасности в памяти (внутри кода приложения) пароли лучше временно держать в массиве символов `char[]`, чтобы их нельзя было случайно считать из кучи (Heap Dump) до очистки сборщиком мусора.
