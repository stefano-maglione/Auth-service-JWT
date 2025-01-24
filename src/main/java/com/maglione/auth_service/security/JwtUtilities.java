package com.maglione.auth_service.security;


import com.maglione.auth_service.exception.InvalidFingerprintException;
import com.maglione.auth_service.exception.JwtAuthenticationException;
import io.jsonwebtoken.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.function.Function;

@Slf4j
@Component
public class JwtUtilities {


    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long jwtExpiration;


    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String email = extractUsername(token);
        return (email.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(String email, List<String> roles, String fingerprint) {

        return Jwts.builder()
                .setSubject(email)
                .claim("role", roles)
                .claim("fingerprint", hashFingerprint(fingerprint))
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(Date.from(Instant.now().plus(jwtExpiration, ChronoUnit.MILLIS)))
                .signWith(SignatureAlgorithm.HS256, secret).compact();
    }

    public boolean validateToken(String token, String fingerprint) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(secret)
                    .parseClaimsJws(token)
                    .getBody();

            // Extract the fingerprint from the token and hash the provided fingerprint
            String tokenFingerprintHash = claims.get("fingerprint", String.class);
            String requestFingerprintHash = hashFingerprint(fingerprint);

            if (!tokenFingerprintHash.equals(requestFingerprintHash)) {
                throw new InvalidFingerprintException("Fingerprint mismatch detected. Possible session hijacking attempt.");
            }

            return true;

        } catch (InvalidFingerprintException e) {
            log.info("Fingerprint mismatch detected. Possible session hijacking attempt.");
            throw new InvalidFingerprintException("Fingerprint mismatch detected. Possible session hijacking attempt.", e);

        } catch (ExpiredJwtException e) {
            log.info("Expired JWT token.");
            throw new JwtAuthenticationException("Token expired", e);
        } catch (SignatureException e) {
            log.info("Invalid JWT signature.");
            throw new JwtAuthenticationException("Invalid token signature", e);
        } catch (MalformedJwtException e) {
            log.info("Invalid JWT token.");
            throw new JwtAuthenticationException("Malformed token", e);
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT token.");
            throw new JwtAuthenticationException("Unsupported token", e);
        } catch (IllegalArgumentException e) {
            log.info("Invalid JWT claims.");
            throw new JwtAuthenticationException("Illegal JWT argument", e);
        }
    }


    public String getToken(HttpServletRequest httpServletRequest) {
        final String bearerToken = httpServletRequest.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }


    public String generateFingerprint() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }


    public String hashFingerprint(String fingerprint) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(fingerprint.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error hashing fingerprint", e);
        }
    }

}
