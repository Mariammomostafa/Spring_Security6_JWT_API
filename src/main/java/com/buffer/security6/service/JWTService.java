package com.buffer.security6.service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.buffer.security6.entity.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JWTService {
	
	private  String secretKey=null;

	public String generateToken(User user) {
		
		Map<String, Object> claims= new HashMap<>();
		
		return Jwts.builder()
				           .claims()
				           .add(claims)
				           .subject(user.getUsername())
				           .issuedAt(new Date(System.currentTimeMillis()))
				           .expiration(new Date(System.currentTimeMillis()+60*10*1000))
				           .and()
				           .signWith(generateKey())
				           .compact();
	}
	
	private SecretKey generateKey() {
		  byte[] decode = Decoders.BASE64.decode(getSecretKey());
		return Keys.hmacShaKeyFor(decode);
	}

	public String getSecretKey() {
		return secretKey="bea091fdfd62f1ed9cbd340c96a3ef202e440e4b6844008b5f40cf5b71efacc58839dd9f27a851e4e3af21fcd1aaf85882dac37b97051184e4018d7a12408c5f";
		
	}

	public String getUsernameFromToken(String token) {
		
		return extractClaims(token , Claims::getSubject);
	}

	private <T>T extractClaims(String token, Function<Claims, T> claimResolver) {
		Claims claims= extractClaims(token);
		return claimResolver.apply(claims);
	}

	private Claims extractClaims(String token) {
		
		return Jwts
				          .parser()
				          .verifyWith(generateKey())
				          .build()
				          .parseSignedClaims(token)
				          .getPayload();
	}

	public boolean isTokenValid(String token, UserDetails userDetails) {
	
		final String username= getUsernameFromToken(token);
		return (username.equals(userDetails.getUsername())  && !isTokenExpired(token));
	}

	private boolean isTokenExpired(String token) {
		
		return extractExpirationDate(token).before(new Date());
	}

	private Date extractExpirationDate(String token) {
		return extractClaims(token, Claims::getExpiration);
	}

	
}
