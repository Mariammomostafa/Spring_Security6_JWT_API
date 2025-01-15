package com.buffer.security6.config;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.buffer.security6.service.JWTService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
	
	private final JWTService jwtService;
	private final UserDetailsService userDetailsService;
	
	public JwtAuthenticationFilter(JWTService jwtService, UserDetailsService userDetailsService) {
		super();
		this.jwtService = jwtService;
		this.userDetailsService = userDetailsService;
	}


	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		final String authHeader=request.getHeader("Authorization");
		
		if(authHeader == null || !authHeader.startsWith("Bearer")) {
			filterChain.doFilter(request, response);
			return;
		}
		
		String jwt = authHeader.substring(7);
		String username = jwtService.getUsernameFromToken(jwt);
		
		Authentication authentication=
				         SecurityContextHolder.getContext().getAuthentication();
		
		// if i have username from token and i am NOT authenticated for this request , So i need to authenticate from this token instead of enter username and password
		if(username != null && authentication == null) {
			
			UserDetails  userDetails= userDetailsService.loadUserByUsername(username);
			
			if(jwtService.isTokenValid(jwt , userDetails)) {
				
				// setting userDetails inside authenticationToken
				UsernamePasswordAuthenticationToken authenticationToken =
						 new UsernamePasswordAuthenticationToken(userDetails, null , userDetails.getAuthorities());
				
				// setting session Id inside authenticationToken
				authenticationToken.setDetails(
						new WebAuthenticationDetailsSource().buildDetails(request));
				
				// setting authenticationToken inside context after Authentication was null
				SecurityContextHolder.getContext().setAuthentication(authenticationToken);
				
				}
			
		}
		//calling the next filter
		filterChain.doFilter(request, response);		
	}

}
