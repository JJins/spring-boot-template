package com.example.demo.security;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.example.demo.User;
import com.example.demo.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {

    private final UserService userService;

    public JwtAuthFilter(UserService userService) {
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        String token = JwtUtil.getToken(request);
        if (null != token) {
            try {
                String username = JwtUtil.getUsernameFromToken(token);
                if (JwtUtil.verify(token, username)) {
                    Authentication auth = userService.getOne(new LambdaQueryWrapper<User>().eq(User::getUsername, username));
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            } catch (Exception e) {
/*
            SecurityContextHolder.clearContext();
            response.sendError(HttpStatus.UNAUTHORIZED.value(), e.getMessage());
            return;
*/
                log.error("{}", e.getMessage());
            }
        }

        filterChain.doFilter(request, response);
    }
}
