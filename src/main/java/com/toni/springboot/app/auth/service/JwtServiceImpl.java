package com.toni.springboot.app.auth.service;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.toni.springboot.app.auth.SimpleGrantedAuthorityMixin;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtServiceImpl implements JwtService {
	
	public static final String SECRET = Base64Utils.encodeToString("alguna.clave.secreta.12345".getBytes());

	public static final long EXPIRATION_DATE = 14000000L;
	
	public static final String TOKEN_PREFIX = "Bearer ";
	
	public static final String HEADER_STRING = "Authorization";
	
	@Override
	public String create(Authentication auth) throws IOException {
		String username = ((User)auth.getPrincipal()).getUsername();
		
		Collection<? extends GrantedAuthority> roles = auth.getAuthorities();
		
		Claims claims = Jwts.claims();
		claims.put("authorities", new ObjectMapper().writeValueAsString(roles));
		
		/*String token = Jwts.builder()
		.setSubject(username)
		.signWith(SignatureAlgorithm.HS512, "Alguna.Clave.Secreta.12345".getBytes())
		.compact();*/
		
		SecretKey secretKey = new SecretKeySpec(SECRET.getBytes(), SignatureAlgorithm.HS512.getJcaName());
		//SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);
		
        String token = Jwts.builder()
        				.setClaims(claims)
                        .setSubject(username)
                        .signWith(secretKey)
                        .setIssuedAt(new Date())
                        .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_DATE) )
                        .compact();
		return token;
	}

	@Override
	public boolean validate(String token) {
		try {
			getClaims(token);
			return true;
		} catch (JwtException | IllegalArgumentException e) {
			return false;
		}
	}

	@Override
	public Claims getClaims(String token) {
		return  Jwts.parser()
                .setSigningKey(SECRET)
                .parseClaimsJws(resolve(token)).getBody();
		//Jwts.parserBuilder()
		//.setSigningKey("alguna.clave.secreta.12345".getBytes());
		
		/*Jwts.parser()
		.setSigningKey("alguna.clave.secreta.12345".getBytes())
		.parseClaimsJws(header.replace("Bearer ", "")).getBody(); */
	}

	@Override
	public String getUsername(String token) {
		return getClaims(token).getSubject();
	}

	@Override
	public Collection<? extends GrantedAuthority> getRoles(String token) throws IOException {
		Object roles = getClaims(token).get("authorities");
		
		return Arrays.asList(new ObjectMapper()
				.addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class)
				.readValue(roles.toString().getBytes(), SimpleGrantedAuthority[].class));
	}

	@Override
	public String resolve(String token) {
		if (token != null && token.startsWith(TOKEN_PREFIX)) {
			return token.replace(TOKEN_PREFIX, token);
		}
		return null;
	}

}
