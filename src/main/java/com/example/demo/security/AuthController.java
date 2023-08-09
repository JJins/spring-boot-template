package com.example.demo.security;

import com.example.demo.User;
import com.example.demo.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/api/login")
    public ResponseEntity<String[]> login(@RequestBody Map<String, Object> vo) {
        String username = (String) vo.get("username");
        String password = (String) vo.get("password");
        Assert.hasLength(username, "用户名不能为空");
        Assert.hasLength(password, "密码不能为空");
        User user = userService.getOneByUsername(username);
        if (null != user && password.equals(user.getPassword())) {
            SecurityContextHolder.getContext().setAuthentication(user);
            return ResponseEntity.ok(new String[]{JwtUtil.sign(username)});
        } else {
            return ResponseEntity.ok(new String[]{"用户名与密码不匹配"});
        }
    }

}
