package ro.thedotin.springcloudgwdemo.config;

import org.springframework.security.core.userdetails.UserDetails;

import java.util.Objects;

public class AccessValidation {

    private final UserDetails user;

    public AccessValidation(UserDetails user) {
        this.user = user;
    }

    public boolean hasRole(String role) {
        if (this.user == null) return false;
        return user.getAuthorities().stream().anyMatch(auth -> Objects.equals(auth.getAuthority(), role));
    }
}
