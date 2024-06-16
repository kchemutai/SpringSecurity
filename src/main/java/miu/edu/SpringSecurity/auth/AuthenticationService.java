package miu.edu.SpringSecurity.auth;

import lombok.RequiredArgsConstructor;
import miu.edu.SpringSecurity.config.JwtService;
import miu.edu.SpringSecurity.user.User;
import miu.edu.SpringSecurity.user.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest registerRequest) {
        //create user from data from the registration request
        User user = new User(
                registerRequest.getFirstName(),
                registerRequest.getLastName(),
                registerRequest.getEmail(),
                passwordEncoder.encode(registerRequest.getPassword()),
                registerRequest.getRole()
        );

        //save user
        User savedUser = userRepository.save(user);

        //generate token
        String token = jwtService.generateToken(savedUser);
        return new AuthenticationResponse(token);
    }
    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationRequest.getEmail(),
                        authenticationRequest.getPassword()
                )

        );
        var user = userRepository.findByEmail(authenticationRequest.getEmail()).orElseThrow(()->new RuntimeException(authenticationRequest.getEmail()));
        String token = jwtService.generateToken(user);
        return new AuthenticationResponse(token);
    }
}
