package com.aplussoft.springjwtauth.security;

import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtUtils {

	@Value("${application.jwt.secretKeyString}")
	private String secretKeyString;

	@Value("${application.jwt.expiration}")
	private long expiration;

	@Value("${application.jwt.tokenPrefix}")
	private String tokenPrefix;

	@Value("${application.jwt.authrorizationHeader}")
	private String authrorizationHeader;

	public JwtUtils() {
	}

	public Jws<Claims> claims(String token) {
		return Jwts.parser()
				.verifyWith(getSecretKey())
				.build()
				.parseSignedClaims(token);
	}

	public Claims payload(String token) {
		return claims(token).getPayload();
	}

	public String extractUsername(String token) {
		return payload(token).getSubject();
	}

	public boolean isTokenValid(String token, UserDetails userDetails) {

		final String username = extractUsername(token);

		return username.equals(userDetails.getUsername()) && !isExpired(token);
	}

	private boolean isExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	private Date extractExpiration(String token) {
		return payload(token).getExpiration();
	}

	public String getTokenPrefix() {
		return tokenPrefix;
	}

	public String getAuthrorizationHeader() {
		return authrorizationHeader;
	}

	public String generateJwt(UserDetails userDetails) {
		return Jwts.builder()
				.subject(userDetails.getUsername())
				.claim("authorities", userDetails.getAuthorities())
				.issuedAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(System.currentTimeMillis() + expiration))
				.signWith(getSecretKey())
				.compact();
	}

	public SecretKey getSecretKey() {
		byte[] keyBytes = Decoders.BASE64.decode(secretKeyString);
		return Keys.hmacShaKeyFor(keyBytes);
	}

}
