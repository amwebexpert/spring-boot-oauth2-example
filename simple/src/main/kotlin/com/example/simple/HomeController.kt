package com.example.simple

import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.security.Principal


@RestController
class HomeController {

    @RequestMapping("/user")
    fun user(principal: Principal): Principal {
        return principal
    }

}