package com.example.demo.service;

import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Service: business logic register & login.
 *
 * Keamanan SQL injection:
 * - Akses DB hanya lewat JpaRepository (prepared statement + parameter binding),
 *   tidak ada string concatenation ke SQL.
 * - sanitize() hanya untuk normalisasi/validasi input (trim, buang kontrol char,
 *   batas panjang, format email), bukan sebagai pertahanan utama SQLi.
 */
@Service
public class UserService {

    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}$");

    private static final int MAX_EMAIL_LENGTH = 254;
    private static final int MIN_PASSWORD_LENGTH = 8;
    private static final int MAX_PASSWORD_LENGTH = 72; // batas input BCrypt

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository repository, PasswordEncoder passwordEncoder) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
    }

    public enum RegisterResult {
        SUCCESS, ALREADY_EXISTS, INVALID_EMAIL, INVALID_PASSWORD
    }

    public record RegisterOutcome(RegisterResult result, String message) {
    }

    public enum LoginResult {
        SUCCESS, INCORRECT, INVALID_INPUT
    }

    public RegisterOutcome register(String rawEmail, String rawPassword) {
        String email = sanitizeEmail(rawEmail);
        if (email == null) {
            return new RegisterOutcome(RegisterResult.INVALID_EMAIL, "Invalid email format");
        }
        String password = sanitizePassword(rawPassword);
        if (password == null) {
            return new RegisterOutcome(RegisterResult.INVALID_PASSWORD, "Invalid password");
        }
        String passwordError = validatePasswordPolicy(password);
        if (passwordError != null) {
            return new RegisterOutcome(RegisterResult.INVALID_PASSWORD, passwordError);
        }
        if (repository.existsByEmail(email)) {
            return new RegisterOutcome(RegisterResult.ALREADY_EXISTS, "Email already registered");
        }
        User user = new User(email, passwordEncoder.encode(password));
        repository.save(user);
        return new RegisterOutcome(RegisterResult.SUCCESS, "User registered successfully.");
    }

    /**
     * Kebijakan password register: minimal 8 karakter, wajib ada
     * 1 huruf besar, 1 huruf kecil, 1 angka, dan 1 special character
     * (karakter non-alfanumerik). Return pesan error atau null jika lolos.
     */
    static String validatePasswordPolicy(String password) {
        if (password.length() < MIN_PASSWORD_LENGTH) {
            return "Password must be at least 8 characters";
        }
        if (!password.chars().anyMatch(Character::isUpperCase)) {
            return "Password must contain at least 1 uppercase letter";
        }
        if (!password.chars().anyMatch(Character::isLowerCase)) {
            return "Password must contain at least 1 lowercase letter";
        }
        if (!password.chars().anyMatch(Character::isDigit)) {
            return "Password must contain at least 1 digit";
        }
        if (!password.chars().anyMatch(c -> !Character.isLetterOrDigit(c))) {
            return "Password must contain at least 1 special character";
        }
        return null;
    }

    public LoginResult login(String rawEmail, String rawPassword) {
        String email = sanitizeEmail(rawEmail);
        String password = sanitizePassword(rawPassword);
        if (email == null || password == null) {
            return LoginResult.INVALID_INPUT;
        }
        Optional<User> found = repository.findByEmail(email);
        if (found.isEmpty()) {
            return LoginResult.INCORRECT;
        }
        if (!passwordEncoder.matches(password, found.get().getPassword())) {
            return LoginResult.INCORRECT;
        }
        return LoginResult.SUCCESS;
    }

    /**
     * Normalisasi email: trim, lowercase, buang null-byte & karakter kontrol,
     * cek panjang dan format. Return null jika tidak valid.
     */
    static String sanitizeEmail(String input) {
        if (input == null) {
            return null;
        }
        String cleaned = stripDangerousChars(input.trim().toLowerCase(Locale.ROOT));
        if (cleaned.isEmpty() || cleaned.length() > MAX_EMAIL_LENGTH) {
            return null;
        }
        if (!EMAIL_PATTERN.matcher(cleaned).matches()) {
            return null;
        }
        return cleaned;
    }

    /**
     * Sanitasi password: trim spasi tepi TIDAK dilakukan agresif (spasi bisa
     * bagian dari password), tapi buang null-byte & karakter kontrol dan
     * batasi panjang. Return null jika kosong/terlalu panjang.
     */
    static String sanitizePassword(String input) {
        if (input == null) {
            return null;
        }
        String cleaned = stripDangerousChars(input);
        if (cleaned.isEmpty() || cleaned.length() > MAX_PASSWORD_LENGTH) {
            return null;
        }
        return cleaned;
    }

    /** Buang null byte dan karakter kontrol C0/C1 (sering dipakai smuggling/truncation). */
    private static String stripDangerousChars(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\0' || (c < 0x20 && c != '\t') || (c >= 0x7F && c <= 0x9F)) {
                continue;
            }
            sb.append(c);
        }
        return sb.toString();
    }
}
