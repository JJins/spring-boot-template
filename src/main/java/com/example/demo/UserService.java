package com.example.demo;

import com.baomidou.mybatisplus.extension.service.IService;

public interface UserService extends IService<User> {
    User getOneByUsername(String username);
}
