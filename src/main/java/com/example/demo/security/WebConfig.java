package com.example.demo.security;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.example.demo.User;
import com.example.demo.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebConfig {
    private final UserService userService;
    private final JwtAuthFilter jwtAuthFilter;
    private final MyAuthEntryPoint myAuthEntryPoint;

    public WebConfig(UserService userService, JwtAuthFilter jwtAuthFilter, MyAuthEntryPoint myAuthEntryPoint) {
        this.userService = userService;
        this.jwtAuthFilter = jwtAuthFilter;
        this.myAuthEntryPoint = myAuthEntryPoint;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            User user = userService.getOne(new LambdaQueryWrapper<User>().eq(User::getUsername, username));
            if (user == null) throw new UsernameNotFoundException("用户名不存在");
            return user;
        };
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                .cors(Customizer.withDefaults())

                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/login").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)

                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)

                .sessionManagement(sessionMgr -> sessionMgr.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(exHdl -> exHdl.authenticationEntryPoint(myAuthEntryPoint));

        return http.build();
    }

}
