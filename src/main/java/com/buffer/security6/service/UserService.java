package com.buffer.security6.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.buffer.security6.entity.User;
import com.buffer.security6.repository.UserRepository;

@Service
public class UserService {
	
	private final UserRepository userRepository;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;
	private final AuthenticationManager authenticationManager;
	private final JWTService jwtService;
	
	public UserService(UserRepository userRepository
			, BCryptPasswordEncoder bCryptPasswordEncoder
			,AuthenticationManager authenticationManager, JWTService jwtService) {
		
		super();
		this.userRepository = userRepository;
		this.bCryptPasswordEncoder = bCryptPasswordEncoder;
		this.authenticationManager = authenticationManager;
		this.jwtService = jwtService;
	}

	
	public User register(User user) {
		
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		return userRepository.save(user);
	}


	public String verify(User user) {
		
		Authentication authentication =
				authenticationManager.authenticate(
						new UsernamePasswordAuthenticationToken(
								user.getUsername(), user.getPassword()));
		

		if(authentication.isAuthenticated())
			return jwtService.generateToken(user);
		return "You are logged successfully ....";
	}
	
	
	
}
