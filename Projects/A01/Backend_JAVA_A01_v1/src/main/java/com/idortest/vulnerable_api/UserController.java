package com.idortest.vulnerable_api;

import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;


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
