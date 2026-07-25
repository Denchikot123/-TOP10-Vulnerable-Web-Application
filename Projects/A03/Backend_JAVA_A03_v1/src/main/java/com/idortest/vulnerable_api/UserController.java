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
import org.springframework.security.crypto.password.PasswordEncoder;

@RestController
public class UserController {
    
    private final JdbcTemplate jdbcTemplate;
    private final PasswordEncoder passwordEncoder;

    public UserController(JdbcTemplate jdbcTemplate, PasswordEncoder passwordEncoder) {
        this.jdbcTemplate = jdbcTemplate;
        this.passwordEncoder = passwordEncoder;
    }
    
    @GetMapping("/api/profile")
    public Map<String, Object> getProfile(HttpSession session) {
        Object userId = session.getAttribute("userId");
        if (userId == null) {
            throw new RuntimeException("Ошибка: Вы не авторизованы!");
        }

        String sql = "SELECT username, secret_note FROM users WHERE id = '" + userId + "'";
        return jdbcTemplate.queryForMap(sql);
    }
    
    @GetMapping("/api/users/list")
    public List<Map<String, Object>> listUsers() {
        return jdbcTemplate.queryForList("SELECT id, username FROM users");
    }

    @PostMapping("/api/auth/login")
    public String login(@RequestBody Map<String, String> request, HttpSession session) {
        String username = request.get("username");
        String password = request.get("password");

        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        
        try {
            Map<String, Object> user = jdbcTemplate.queryForMap(sql);

            String hashedPasswordFromDB = (String) user.get("password");
            if (passwordEncoder.matches(password, hashedPasswordFromDB)) {
                session.setAttribute("userId", user.get("id"));
                session.setAttribute("username", user.get("username"));
                return "Добро пожаловать, " + user.get("username");
            } else {
                return "Ошибка: Неверный логин или пароль";
            }
        } catch (Exception e) {
            return "Ошибка: Неверный логин или пароль";
        } 
    }

    @PostMapping("/api/auth/register")
    public String register(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String password = request.get("password");
        String secretNote = request.get("secret_note");

        String hashedPassword = passwordEncoder.encode(password);

        String sql = "INSERT INTO users (username, password, secret_note) VALUES (?, ?, ?)";
        jdbcTemplate.update(sql, username, hashedPassword, secretNote);

        return "Профиль " + username  + " успешно зарегестрирован";
    }
}
