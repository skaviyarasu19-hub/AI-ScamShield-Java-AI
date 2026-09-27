package com.scamshield.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.scamshield.dto.LoginRequest;
import com.scamshield.dto.RegisterRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void registerThenLogin_succeeds() throws Exception {
        RegisterRequest register = new RegisterRequest();
        register.setUsername("junituser");
        register.setEmail("junituser@example.com");
        register.setPassword("Password123");

        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(register)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.username").value("junituser"));

        LoginRequest login = new LoginRequest();
        login.setUsername("junituser");
        login.setPassword("Password123");

        mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(login)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists());
    }

    @Test
    void registerWithInvalidEmail_returnsBadRequest() throws Exception {
        RegisterRequest register = new RegisterRequest();
        register.setUsername("baduser");
        register.setEmail("not-an-email");
        register.setPassword("Password123");

        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(register)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void loginWithWrongPassword_returnsUnauthorized() throws Exception {
        RegisterRequest register = new RegisterRequest();
        register.setUsername("wrongpassuser");
        register.setEmail("wrongpassuser@example.com");
        register.setPassword("Password123");

        mockMvc.perform(post("/api/auth/register")
                .contentType("application/json")
                .content(objectMapper.writeValueAsString(register)));

        LoginRequest login = new LoginRequest();
        login.setUsername("wrongpassuser");
        login.setPassword("WrongPassword");

        mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(login)))
                .andExpect(status().isUnauthorized());
    }
}
