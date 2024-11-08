package com.isuisu.sign.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Set;

@Entity
@Getter
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;

    private String nickname;

    // 간단하게 ElementCollection 으로 구현
    @Column(nullable = false)
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Enumerated(EnumType.STRING)
    private Set<UserRole> authorities;

    public User(String username, String password, String nickname, Set<UserRole> authorities) {
        this.username = username;
        this.password = password;
        this.nickname = nickname;
        this.authorities = authorities;
    }

    public static User signUp(String username, String password, String nickname, Set<UserRole> authorities) {
        return new User(username, password, nickname, authorities);
    }
}
