# Spring Boot JWT - 회원가입/로그인

## File structure
```
com.isuisu.sign
├── configuration
├── controller
├── dto
├── mapper
├── model
├── exception
├── repository
├── security
└── service
```

## Endpoint
`POST` /api/signup   
`POST` /api/signin

## Table
### users
|Column|Type| Description                |
|------------|--------------|----------------------------|
| id         | Long         | Primary Key, 사용자 고유 ID     |
| username   | String       | 로그인에 사용되는 사용자 아이디, Null 불가 |
| password   | String       | 암호화된 사용자 비밀번호, Null 불가     |
| nickname   | String       | 사용자의 별명, Null 허용           |
| authorities | Enum (String) | 사용자의 권한 수준, Null 불가        |

### refresh_tokens
|Column|Type| Description             |
| --- | --- | --- |
| id | Long | Primary Key, 고유 식별자 |
| userId | Long | 사용자 ID, Null 불가 |
| refreshToken | String | 리프레시 토큰 값, Null 불가 |
