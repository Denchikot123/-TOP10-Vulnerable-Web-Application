package com.idortest.vulnerable_api;

import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import jakarta.servlet.http.HttpSession;

@RestController
public class UserController {
    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    @GetMapping("/api/profile")
    public Map<String, Object> getProfile(HttpSession session) {
        Object userId = session.getAttribute("userId");
        if (userId == null) {
            throw new RuntimeException("Ошибка: Вы не авторизованы!");
        }

        // Классический IDOR + SQL-инъекция
        String sql = "SELECT username, secret_note FROM users WHERE id = '" + userId + "'";
        return jdbcTemplate.queryForMap(sql);
    }
    
    @GetMapping("/api/users/list")
    public List<Map<String, Object>> listUsers() {
        return jdbcTemplate.queryForList("SELECT id, username FROM users");
    }

    @PostMapping("/api/auth/login")
    public String login(@RequestBody Map<String, String> request, HttpSession session) { // <-- Добавили HttpSession сессию сюда
        String username = request.get("username");
        String password = request.get("password");

        // Классическая SQL-инъекция в авторизации
        String sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        
        try {
            Map<String, Object> user = jdbcTemplate.queryForMap(sql); // <-- Поставили ;

            session.setAttribute("userId", user.get("id"));
            session.setAttribute("username", user.get("username"));

            return "Добро пожаловать, " + user.get("username"); // <-- Поставили ;
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

        return "User registered successfully in plain text!";
    }
}
