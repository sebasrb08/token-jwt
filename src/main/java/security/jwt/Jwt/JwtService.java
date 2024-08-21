package security.jwt.Jwt;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;


@Service
public class JwtService {

    private static final String SECRET_KEY="121564165151a65sd165a1sd4adsasd0a1sd0";
    private SecretKey key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));//DETERMINA AUTOMATICAMENTE EL ALGORITMO HMAC a usar segun la longitud de la clave


    public String getToken(UserDetails user) {
        return getToken(new HashMap<>(),user);
    }

    private String getToken(Map<String,Object> extraClaims, UserDetails user) {


        return Jwts.builder()//construimos el objeto
                .claims(extraClaims)//aquí se añaden los claims adicionales los cuales son los datos que se incluyen en el payload
                .subject(user.getUsername())// El nombre de usuario se establece como el sujeto (subject)
                .issuedAt(new Date(System.currentTimeMillis()))// Fecha de emisión
                .expiration(new Date(System.currentTimeMillis()+1000*60*24))// Fecha de expiración
                .signWith(key) // Se firma con la clave secreta
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
       final String username = getUsernameFromToken(token);
       // Compara el nombre de usuario extraído del token con el nombre de usuario en los detalles del usuario.
        // Luego verifica si el token no ha expirado.
       return (username.equals(userDetails.getUsername())&& !isTokenExpired(token));
    }

    public String getUsernameFromToken(String token) {
        // Extrae y devuelve el nombre de usuario (subject) del token.
        return getClaim(token, Claims::getSubject);
    }

    public Claims getAllClaims(String token){
        // Parsea el token JWT para extraer todas las claims (declaraciones) contenidas en él.
        return Jwts.parser()
        .verifyWith(key) // Verifica la firma del token usando la clave secreta.
        .build() // Construye el parser JWT.
        .parseSignedClaims(token) // Parsea el token firmado.
        .getPayload();  // Obtiene el payload (claims) del token.
    }

    public <T> T getClaim(String token,Function<Claims,T> clainsResolver){
        // Extrae una claim específica del token usando una función que determina qué claim obtener.
        final Claims claims =getAllClaims(token);
        return clainsResolver.apply(claims);

    }

    private Date getExpiration(String token){
        // Extrae la fecha de expiración del token.
        return getClaim(token,Claims::getExpiration);
    }

    private boolean isTokenExpired(String token){
        // Verifica si el token ha expirado comparando la fecha de expiración con la fecha actual.
        return getExpiration(token).before(new Date());
    }




}
