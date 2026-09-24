package com.example.demo.controller;

import com.example.demo.service.UserService;
import com.example.demo.service.UserService.LoginResult;
import com.example.demo.service.UserService.RegisterOutcome;
import com.example.demo.service.UserService.RegisterResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Slice test Controller via standalone MockMvc (tanpa Spring context):
 * memastikan mapping URL, Content-Type form-urlencoded, dan status HTTP.
 */
class AuthControllerTest {

    private static final MediaType FORM = MediaType.APPLICATION_FORM_URLENCODED;

    private UserService service;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        service = mock(UserService.class);
        mockMvc = MockMvcBuilders.standaloneSetup(new AuthController(service)).build();
    }

    @Test
    void register_sukses_200() throws Exception {
        when(service.register("test@example.com", "Strong1!"))
                .thenReturn(new RegisterOutcome(RegisterResult.SUCCESS, "User registered successfully."));

        mockMvc.perform(post("/register").contentType(FORM)
                        .param("email", "test@example.com")
                        .param("password", "Strong1!"))
                .andExpect(status().isOk())
                .andExpect(content().string("User registered successfully."));
    }

    @Test
    void register_duplikat_409() throws Exception {
        when(service.register("test@example.com", "Strong1!"))
                .thenReturn(new RegisterOutcome(RegisterResult.ALREADY_EXISTS, "Email already registered"));

        mockMvc.perform(post("/register").contentType(FORM)
                        .param("email", "test@example.com")
                        .param("password", "Strong1!"))
                .andExpect(status().isConflict())
                .andExpect(content().string("Email already registered"));
    }

    @Test
    void register_emailTidakValid_400() throws Exception {
        when(service.register("bukan-email", "Strong1!"))
                .thenReturn(new RegisterOutcome(RegisterResult.INVALID_EMAIL, "Invalid email format"));

        mockMvc.perform(post("/register").contentType(FORM)
                        .param("email", "bukan-email")
                        .param("password", "Strong1!"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Invalid email format"));
    }

    @Test
    void register_passwordLemah_400() throws Exception {
        when(service.register("test@example.com", "weak"))
                .thenReturn(new RegisterOutcome(
                        RegisterResult.INVALID_PASSWORD, "Password must be at least 8 characters"));

        mockMvc.perform(post("/register").contentType(FORM)
                        .param("email", "test@example.com")
                        .param("password", "weak"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Password must be at least 8 characters"));
    }

    @Test
    void register_paramHilang_400() throws Exception {
        mockMvc.perform(post("/register").contentType(FORM)
                        .param("email", "test@example.com"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void register_bodyJson_ditolak415() throws Exception {
        mockMvc.perform(post("/register").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"test@example.com\",\"password\":\"Strong1!\"}"))
                .andExpect(status().isUnsupportedMediaType());
    }

    @Test
    void login_sukses_200() throws Exception {
        when(service.login("test@example.com", "Strong1!")).thenReturn(LoginResult.SUCCESS);

        mockMvc.perform(post("/login").contentType(FORM)
                        .param("email", "test@example.com")
                        .param("password", "Strong1!"))
                .andExpect(status().isOk())
                .andExpect(content().string("Login successful"));
    }

    @Test
    void login_salah_401() throws Exception {
        when(service.login("test@example.com", "Wrong1!x")).thenReturn(LoginResult.INCORRECT);

        mockMvc.perform(post("/login").contentType(FORM)
                        .param("email", "test@example.com")
                        .param("password", "Wrong1!x"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Email / Password Incorrect"));
    }

    @Test
    void login_inputTidakValid_400() throws Exception {
        when(service.login("bukan-email", "x")).thenReturn(LoginResult.INVALID_INPUT);

        mockMvc.perform(post("/login").contentType(FORM)
                        .param("email", "bukan-email")
                        .param("password", "x"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Invalid email or password"));
    }
}
