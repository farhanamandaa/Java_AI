package com.example.demo.repository;

import com.example.demo.model.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Verifikasi lapisan JPA di H2: simpan, cari by email, dan unique constraint.
 */
@DataJpaTest
class UserRepositoryTest {

    @Autowired
    private UserRepository repository;

    @Test
    void simpanDanCariByEmail() {
        repository.save(new User("test@example.com", "hashed-pw"));

        assertThat(repository.findByEmail("test@example.com")).isPresent();
        assertThat(repository.existsByEmail("test@example.com")).isTrue();
        assertThat(repository.findByEmail("nope@example.com")).isEmpty();
        assertThat(repository.existsByEmail("nope@example.com")).isFalse();
    }

    @Test
    void emailDuplikat_ditolakDatabase() {
        repository.saveAndFlush(new User("dup@example.com", "hash-1"));

        assertThatThrownBy(() -> repository.saveAndFlush(new User("dup@example.com", "hash-2")))
                .isInstanceOf(DataIntegrityViolationException.class);
    }
}
