package boot.util;

import boot.domain.exceptions.AuthenticationException;
import boot.domain.exceptions.UserDefinedException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.crypto.MacProvider;
import java.security.Key;
import java.util.Calendar;
import java.util.Date;

public class JWT {

    private static final Key key = MacProvider.generateKey();
    private static final int TOKEN_EXPIRATION_TIME = 1200000;
    //private static final int TOKEN_EXPIRATION_REFRESH_TIME = 600000;


    public static String buildToken( String jsonClaim){
        Calendar date = Calendar.getInstance();
        long t = date.getTimeInMillis();
        return Jwts.builder()
                .setSubject(jsonClaim)
                .setIssuedAt(new Date(t))
                .setExpiration(new Date(t + TOKEN_EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS512, key)
                .compact();
    }


    /**
     * Method adds argument as claim and builds token
     * @param user
     * @param <T>
     * @return
     * @throws UserDefinedException
     */
    public static <T> String buildToken( T user) throws UserDefinedException {
        try{
            ObjectMapper mapper = new ObjectMapper();
            String userAsJson = mapper.writeValueAsString(user);

            return JWT.buildToken(userAsJson);
        }catch (JsonProcessingException e) {
            e.printStackTrace();
            throw new UserDefinedException(0, e.getMessage());
        }

    }


    /**
     * Method for checking token.
     * @param token
     * @return If token is valid then return all Claims inside token
     * @throws AuthenticationException
     */
    public static Jws<Claims> checkToken( String token) throws AuthenticationException {
        if (token == null) throw new AuthenticationException();
        try{
            return Jwts.parser().setSigningKey(key).parseClaimsJws(token);
        }catch (Exception e){
            e.printStackTrace();
            throw new AuthenticationException();
        }
    }


    /**
     * Method for checking token.
     * @param token
     * @param userClaim
     * @param <T>
     * @return If token is valid then return User object inside token
     * @throws AuthenticationException
     * If token is not valid then it throws Exceptions.
     */
    public static <T> T checkToken4User(String token, Class<T> userClaim) throws AuthenticationException{
        if (token == null) return null;
        try{
            Jws<Claims> claimsJws = checkToken(token);
            ObjectMapper mappper = new ObjectMapper();
            return mappper.readValue(claimsJws.getBody().getSubject(), (Class<T>) userClaim);
        }catch (Exception e){
            e.printStackTrace();
            throw new AuthenticationException();
        }
    }


    /*public static String refreshToken( String token) throws AuthenticationException{
        Calendar date = Calendar.getInstance();
        Jws<Claims> claimsJws = Jwts.parser().setSigningKey(key).parseClaimsJws(token);

        if (claimsJws != null ){
            if ( claimsJws.getBody().getExpiration().getTime() -  date.getTimeInMillis() <= TOKEN_EXPIRATION_REFRESH_TIME){
                return buildToken(claimsJws.getBody().getSubject());
            }
            return token;
        }
        throw new AuthenticationException();
    }*/

}
