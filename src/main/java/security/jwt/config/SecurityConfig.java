package security.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.security.web.SecurityFilterChain;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    //cadena de filtros que diferencia los endpoint publicos y protegidos
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
        .csrf(crsf -> // desabilitar el cross side rendering
                crsf.disable())
        .authorizeHttpRequests(authRequest -> 
            authRequest
            .requestMatchers("/auth/**").permitAll() // endpoint publico
            .anyRequest().authenticated() //endpoint protegidos
            )
        .formLogin(withDefaults())// Configura el login form con valores por defecto
        .build();
    
       
    }

    // @Bean
    // UserDetailsService userDetailsService(){
    //     InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
    //     manager.createUser(
    //         User.withUsername("admin")
    //         .password(passwordEncoder().encode("admin"))
    //         .roles()
    //         .build()
    //     );
    //     return manager;
    // }

    // /*Administrador de autenticacion */
    // @Bean
    // public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception{
    //     return authenticationConfiguration.getAuthenticationManager();
    // }


    // @Bean
    // public PasswordEncoder passwordEncoder(){
    //     return new BCryptPasswordEncoder();
    // }
}
