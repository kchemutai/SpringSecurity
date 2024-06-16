package miu.edu.SpringSecurity.auth;

import lombok.AllArgsConstructor;
import lombok.Data;
import miu.edu.SpringSecurity.user.Role;

@Data
@AllArgsConstructor
public class RegisterRequest {
    private String firstName;
    private String lastName;
    private String email;
    private String password;
    private Role role;
}
