
# Spring Security with JWT 

This project implement spring security 6 with spring boot 3 , implement registration and login with Jwt token 


## Features
### Registration    and Login

- You can register and login , after login you will have jwt token (which contain information that verifies the identity of a user, and their permissions) and will need to be sent with each request 

### JWT Service
- This class contain methods required for generating jwt token , generate secret key ,  checking if it's valid or not , get expiration date , get username from token , get claims. 

### Jwt Authentication Filter
- This filter occure before (username pasword Authentication filter) and will block all requests that don’t have JWT token in the request header.

### Prerequisites
- Java 17
- Spring Boot 3.4.1
- spring security 6
- Maven
- Postman
- IDE (Eclips)


