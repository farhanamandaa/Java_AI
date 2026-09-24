package com.example.demo.service;

import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import com.example.demo.service.UserService.LoginResult;
import com.example.demo.service.UserService.RegisterOutcome;
import com.example.demo.service.UserService.RegisterResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit test murni (tanpa Spring context): repository di-mock,
 * encoder BCrypt asli agar perilaku hash ikut terverifikasi.
 */
@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository repository;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    private UserService service;

    @BeforeEach
    void setUp() {
        service = new UserService(repository, passwordEncoder);
    }

    @Test
    void register_success_menyimpanHashBukanPlaintext() {
        when(repository.existsByEmail("test@example.com")).thenReturn(false);
        when(repository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        RegisterOutcome outcome = service.register("test@example.com", "Strong1!");

        assertThat(outcome.result()).isEqualTo(RegisterResult.SUCCESS);
        assertThat(outcome.message()).isEqualTo("User registered successfully.");

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(repository).save(captor.capture());
        assertThat(captor.getValue().getEmail()).isEqualTo("test@example.com");
        assertThat(captor.getValue().getPassword()).isNotEqualTo("Strong1!");
        assertThat(passwordEncoder.matches("Strong1!", captor.getValue().getPassword())).isTrue();
    }

    @Test
    void register_emailDinormalisasi_trimDanLowercase() {
        when(repository.existsByEmail("test@example.com")).thenReturn(false);
        when(repository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        RegisterOutcome outcome = service.register("  TEST@Example.COM  ", "Strong1!");

        assertThat(outcome.result()).isEqualTo(RegisterResult.SUCCESS);
        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(repository).save(captor.capture());
        assertThat(captor.getValue().getEmail()).isEqualTo("test@example.com");
    }

    @Test
    void register_duplikat_tidakMenyimpan() {
        when(repository.existsByEmail("test@example.com")).thenReturn(true);

        RegisterOutcome outcome = service.register("test@example.com", "Strong1!");

        assertThat(outcome.result()).isEqualTo(RegisterResult.ALREADY_EXISTS);
        assertThat(outcome.message()).isEqualTo("Email already registered");
        verify(repository, never()).save(any(User.class));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"bukan-email", "a@b", "test@", "@example.com", "test@example.com' OR '1'='1"})
    void register_emailTidakValid_ditolak(String email) {
        RegisterOutcome outcome = service.register(email, "Strong1!");

        assertThat(outcome.result()).isEqualTo(RegisterResult.INVALID_EMAIL);
        assertThat(outcome.message()).isEqualTo("Invalid email format");
        verify(repository, never()).save(any(User.class));
    }

    @ParameterizedTest
    @CsvSource({
            "Ab1!, 'Password must be at least 8 characters'",
            "lowercase1!, 'Password must contain at least 1 uppercase letter'",
            "UPPERCASE1!, 'Password must contain at least 1 lowercase letter'",
            "NoDigit!x, 'Password must contain at least 1 digit'",
            "NoSpecial1, 'Password must contain at least 1 special character'"
    })
    void register_passwordLemah_ditolakDenganPesanSpesifik(String password, String expectedMessage) {
        RegisterOutcome outcome = service.register("test@example.com", password);

        assertThat(outcome.result()).isEqualTo(RegisterResult.INVALID_PASSWORD);
        assertThat(outcome.message()).isEqualTo(expectedMessage);
        verify(repository, never()).save(any(User.class));
    }

    @Test
    void login_sukses() {
        User user = new User("test@example.com", passwordEncoder.encode("Strong1!"));
        when(repository.findByEmail("test@example.com")).thenReturn(Optional.of(user));

        assertThat(service.login("test@example.com", "Strong1!")).isEqualTo(LoginResult.SUCCESS);
    }

    @Test
    void login_passwordSalah() {
        User user = new User("test@example.com", passwordEncoder.encode("Strong1!"));
        when(repository.findByEmail("test@example.com")).thenReturn(Optional.of(user));

        assertThat(service.login("test@example.com", "Wrong1!x")).isEqualTo(LoginResult.INCORRECT);
    }

    @Test
    void login_emailTidakTerdaftar() {
        when(repository.findByEmail("nope@example.com")).thenReturn(Optional.empty());

        assertThat(service.login("nope@example.com", "Strong1!")).isEqualTo(LoginResult.INCORRECT);
    }

    @Test
    void login_inputTidakValid() {
        assertThat(service.login("bukan-email", "Strong1!")).isEqualTo(LoginResult.INVALID_INPUT);
        assertThat(service.login("test@example.com", null)).isEqualTo(LoginResult.INVALID_INPUT);
    }

    @Test
    void login_injeksiSql_tidakLolos() {
        // payload klasik '" OR '1'='1' tidak lolos validasi format email -> INVALID_INPUT,
        // dan kalaupun lolos, repository hanya menerima string sebagai parameter binding
        assertThat(service.login("test@example.com' OR '1'='1", "x"))
                .isEqualTo(LoginResult.INVALID_INPUT);
        verify(repository, never()).findByEmail(any());
    }
}
