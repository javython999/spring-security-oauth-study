package com.errday.springsecurityoauthstudy.repository;

import com.errday.springsecurityoauthstudy.model.users.User;
import org.springframework.stereotype.Repository;

import java.util.HashMap;
import java.util.Map;

@Repository
public class UserRepository {

    private Map<String, Object> users = new HashMap<>();

    public User findByUsername(String username) {
        return users.containsKey(username)
                ? (User) users.get(username)
                : null;
    }

    public void register(User user) {
        if (users.containsKey(user.getUsername())) {
            return;
        }

        users.put(user.getUsername(), user);
    }
}
