package com.example.simple

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso
import org.springframework.boot.runApplication

@SpringBootApplication
@EnableOAuth2Sso
class SocialApplication

fun main(args: Array<String>) {
    runApplication<SocialApplication>(*args)
}
