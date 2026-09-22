package com.iras.security;

import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("JwtAuthenticationFilter — token extraction and SecurityContext population")
class JwtAuthenticationFilterTest {

    private static final String ACCESS_SECRET =
            "test_jwt_access_secret_key_that_is_at_least_32_characters";

    private JwtService jwtService;
    private JwtAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService(ACCESS_SECRET, 900_000L, 604_800_000L);
        filter     = new JwtAuthenticationFilter(jwtService);
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("Valid Bearer token populates SecurityContext with user identity")
    void validBearerToken_populatesSecurityContext() throws Exception {
        String token = jwtService.generateAccessToken(7L, "user@example.com", "CUSTOMER");

        MockHttpServletRequest  request  = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain         chain    = new MockFilterChain();

        request.addHeader("Authorization", "Bearer " + token);
        filter.doFilterInternal(request, response, chain);

        var authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNotNull();
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(authentication.getPrincipal()).isInstanceOf(SecurityUser.class);

        SecurityUser securityUser = (SecurityUser) authentication.getPrincipal();
        assertThat(securityUser.getUsername()).isEqualTo("user@example.com");
        assertThat(securityUser.getId()).isEqualTo(7L);
    }

    @Test
    @DisplayName("No Authorization header leaves SecurityContext empty")
    void noAuthHeader_leavesSecurityContextEmpty() throws Exception {
        MockHttpServletRequest  request  = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain         chain    = new MockFilterChain();

        filter.doFilterInternal(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("Malformed Bearer token leaves SecurityContext empty")
    void malformedToken_leavesSecurityContextEmpty() throws Exception {
        MockHttpServletRequest  request  = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain         chain    = new MockFilterChain();

        request.addHeader("Authorization", "Bearer totally-not-a-jwt");
        filter.doFilterInternal(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("Non-Bearer Authorization header leaves SecurityContext empty")
    void basicAuthHeader_leavesSecurityContextEmpty() throws Exception {
        MockHttpServletRequest  request  = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain         chain    = new MockFilterChain();

        request.addHeader("Authorization", "Basic dXNlcjpwYXNz");
        filter.doFilterInternal(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("Expired token leaves SecurityContext empty")
    void expiredToken_leavesSecurityContextEmpty() throws Exception {
        JwtService shortLived = new JwtService(ACCESS_SECRET, 0L, 604_800_000L);
        String expiredToken   = shortLived.generateAccessToken(1L, "user@example.com", "CUSTOMER");

        // Wait a moment to ensure expiration
        Thread.sleep(10);

        MockHttpServletRequest  request  = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain         chain    = new MockFilterChain();

        request.addHeader("Authorization", "Bearer " + expiredToken);
        filter.doFilterInternal(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("Filter always calls the filter chain")
    void filterAlwaysCallsChain() throws Exception {
        MockHttpServletRequest  request  = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain         chain    = mock(MockFilterChain.class);

        filter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(request, response);
    }
}
