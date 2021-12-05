package com.markerhub.controller;


import com.markerhub.entity.User;
import com.markerhub.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

/**
 *
 * @author hzc
 * @since 2021-11-30
 */
@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    UserService userService;

    @GetMapping("/index")
    public Object index() {
        return userService.getById(1L);
    }

    /**
     * @param user
     * @return
     */
    @PostMapping("/save")
    public Object testUser(@Validated @RequestBody User user) {
        return user.toString();
    }

}




























