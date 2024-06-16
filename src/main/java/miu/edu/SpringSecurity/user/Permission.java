package miu.edu.SpringSecurity.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum Permission {
    ADMIN_WRITE("admin:write"),
    ADMIN_READ("admin:read"),
    MEMBER_WRITE("member:write"),
    MEMBER_READ("member:read");

    @Getter
    private final String permission;
}
