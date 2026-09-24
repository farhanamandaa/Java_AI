package com.example.demo.controller;

import com.example.demo.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller: terima request form-urlencoded, bawa payload ke Service.
 * Tidak ada query SQL / business logic di sini.
 *
 * Contoh curl register:
 * curl -X POST http://localhost:8080/register \
 *   -H "Content-Type: application/x-www-form-urlencoded" \
 *   --data-urlencode "email=test@example.com" \
 *   --data-urlencode "password=Strong1!"
 */
@RestController
public class AuthController {

    private final UserService service;

    public AuthController(UserService service) {
        this.service = service;
    }

    @PostMapping(value = "/register", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<String> register(
            @RequestParam("email") String email,
            @RequestParam("password") String password) {
        UserService.RegisterOutcome outcome = service.register(email, password);
        return switch (outcome.result()) {
            case SUCCESS -> ResponseEntity.ok(outcome.message());
            case ALREADY_EXISTS -> ResponseEntity.status(HttpStatus.CONFLICT).body(outcome.message());
            case INVALID_EMAIL, INVALID_PASSWORD ->
                    ResponseEntity.badRequest().body(outcome.message());
        };
    }

    @PostMapping(value = "/login", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<String> login(
            @RequestParam("email") String email,
            @RequestParam("password") String password) {
        UserService.LoginResult result = service.login(email, password);
        return switch (result) {
            case SUCCESS -> ResponseEntity.ok("Login successful");
            case INCORRECT -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Email / Password Incorrect");
            case INVALID_INPUT -> ResponseEntity.badRequest().body("Invalid email or password");
        };
    }
}
