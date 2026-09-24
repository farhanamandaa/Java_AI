package com.example.demo;

import com.example.demo.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end register -> login lewat HTTP + H2 asli (rollback tiap test).
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuthIntegrationTest {

    private static final MediaType FORM = MediaType.APPLICATION_FORM_URLENCODED;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository repository;

    @Test
    void alurRegisterLoginDuplikat() throws Exception {
        mockMvc.perform(post("/register").contentType(FORM)
                        .param("email", "test@example.com")
                        .param("password", "Strong1!"))
                .andExpect(status().isOk())
                .andExpect(content().string("User registered successfully."));

        // password tersimpan sebagai hash, bukan plaintext
        String stored = repository.findByEmail("test@example.com").orElseThrow().getPassword();
        assertThat(stored).isNotEqualTo("Strong1!");
        assertThat(stored).startsWith("$2");

        mockMvc.perform(post("/login").contentType(FORM)
                        .param("email", "test@example.com")
                        .param("password", "Strong1!"))
                .andExpect(status().isOk())
                .andExpect(content().string("Login successful"));

        mockMvc.perform(post("/register").contentType(FORM)
                        .param("email", "test@example.com")
                        .param("password", "Strong1!"))
                .andExpect(status().isConflict())
                .andExpect(content().string("Email already registered"));

        mockMvc.perform(post("/login").contentType(FORM)
                        .param("email", "test@example.com")
                        .param("password", "Wrong1!x"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("Email / Password Incorrect"));
    }

    @Test
    void register_validasiDitegakkan() throws Exception {
        mockMvc.perform(post("/register").contentType(FORM)
                        .param("email", "bukan-email")
                        .param("password", "Strong1!"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Invalid email format"));

        mockMvc.perform(post("/register").contentType(FORM)
                        .param("email", "weak@example.com")
                        .param("password", "weakpass"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Password must contain at least 1 uppercase letter"));

        assertThat(repository.existsByEmail("bukan-email")).isFalse();
        assertThat(repository.existsByEmail("weak@example.com")).isFalse();
    }

    @Test
    void login_injeksiSql_tidakLolos() throws Exception {
        mockMvc.perform(post("/register").contentType(FORM)
                        .param("email", "victim@example.com")
                        .param("password", "Strong1!"))
                .andExpect(status().isOk());

        mockMvc.perform(post("/login").contentType(FORM)
                        .param("email", "victim@example.com' OR '1'='1")
                        .param("password", "bebas"))
                .andExpect(status().isBadRequest());

        assertThat(repository.count()).isEqualTo(1);
    }
}
