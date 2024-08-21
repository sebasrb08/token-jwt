package security.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import security.jwt.Jwt.JwtAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    AuthenticationProvider authProvider;

    @Autowired
    JwtAuthenticationFilter jwtAuthenticationFilter;

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
        .sessionManagement(sessionManager->
            sessionManager.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        )
        .authenticationProvider(authProvider)
        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        .build();
    
       
    }

}
