package com.hdfc.AdminCredentials.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JWTService {
	
	private static final String SECRET = "f03434d154a068bc0549ac810c3d5802199323b60ebc9cd317854332e6ad80da";

	
	 public String extractUsername(String token) {
		 //System.out.println("inside extract");
	        return extractClaim(token, Claims::getSubject);
	    }

	    public Date extractExpiration(String token) {
	        return extractClaim(token, Claims::getExpiration);
	    }

	    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
	    	//System.out.println("inside claim");
	        final Claims claims = extractAllClaims(token);
	        return claimsResolver.apply(claims);
	    }

	    private Claims extractAllClaims(String token) {
	    	//System.out.println("inside allclaim");
	        return  Jwts.parserBuilder()
		                .setSigningKey(getSignKey())
		                .build()
		                .parseClaimsJws(token)
		                .getBody();
	    }

	    private Boolean isTokenExpired(String token) {
	        return extractExpiration(token).before(new Date());
	    }

	    public Boolean validateToken(String token,UserDetails userDetails) {
	        final String username = extractUsername(token);
	        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	    }
	
	
	public String generateJWTToken(String username) {
		//System.out.println("in generatetoken");
		Map<String,Object> claims = new HashMap<>();
		return createJWTToken(claims,username);
	}

	private String createJWTToken(Map<String, Object> claims, String username) {
		//System.out.println("in createtoken");
		return Jwts.builder()
				.setClaims(claims)
				.setSubject(username)
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis()+1000*30*60))
				.signWith(getSignKey(),SignatureAlgorithm.HS256)
				.compact();
	}

	private Key getSignKey() {
		//System.out.println("in getsignkey");
		byte[] keyBites = Decoders.BASE64.decode(SECRET);
		return  Keys.hmacShaKeyFor(keyBites);
		
	}

}
