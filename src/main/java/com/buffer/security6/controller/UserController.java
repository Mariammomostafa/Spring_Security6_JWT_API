package com.buffer.security6.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.buffer.security6.entity.User;
import com.buffer.security6.repository.UserRepository;
import com.buffer.security6.service.UserService;

@RestController
public class UserController {

	private final UserRepository userRepository;
	private final UserService userService;

	public UserController(UserRepository userRepository,UserService userService) {
		super();
		this.userRepository = userRepository;
		this.userService = userService;
	}
	
	@PostMapping("/register")
	public User register(@RequestBody User user) {
		
		 return userService.register(user);
	}
	
	@PostMapping("/login")
	public String login(@RequestBody User user) {
		
		return userService.verify(user);
		
		
	}
	
	
	
}
