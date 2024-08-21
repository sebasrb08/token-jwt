package security.jwt.Auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import security.jwt.Jwt.JwtService;
import security.jwt.model.Role;
import security.jwt.model.User;
import security.jwt.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class AuthService {

    @Autowired
    private final UserRepository userRepository;

    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
        UserDetails user = userRepository.findByUsername(request.getUsername()).orElseThrow();
        String token = jwtService.getToken(user);
        return AuthResponse.builder()
        .token(token)
        .build();
    }

    public AuthResponse register(RegisterRequest request) {
       User user =User.builder()
       .username(request.getUsername())
       .FirstName(request.getFirstName())
       .LastName(request.getLastName())
       .country(request.getCountry())
       .password(passwordEncoder.encode(request.getPassword()))
       .role(Role.USER)
       .build();

       userRepository.save(user); // Guardando en base de datos el usuario registrado

       return AuthResponse.builder()
                .token(jwtService.getToken(user))
                .build();
    }

}
