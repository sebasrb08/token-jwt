package security.jwt.Auth;

import org.springframework.beans.factory.annotation.Autowired;
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


    public AuthResponse login(LoginRequest request) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'login'");
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
