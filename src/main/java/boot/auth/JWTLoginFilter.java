package boot.auth;

import boot.domain.A;
import boot.domain.exceptions.UserDefinedException;
import boot.util.Constants;
import boot.util.JWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 *
 * Filter for login operation
 *
 */
public class JWTLoginFilter extends AbstractAuthenticationProcessingFilter {

    public JWTLoginFilter(String url, AuthenticationManager authManager) {
        super(new AntPathRequestMatcher(url));
        setAuthenticationManager(authManager);
    }


    /**
     * Method for processing logni operation. Method gets POST json data from request, deserialize it with jackson
     * Object mapper and perform authentication operation
     *
     * @param req Incoming request
     * @param res
     * @return
     * @throws AuthenticationException
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res) throws AuthenticationException, IOException, ServletException {

        //Read request input stream and read json & deserialize to AccountCredentials object.
        System.out.println("11");
        ServletInputStream inputStream = req.getInputStream();
        A a = new ObjectMapper().readValue(inputStream, A.class);
        try {
            String token = JWT.buildToken(a);

            System.out.println("token = " + token);
        } catch (UserDefinedException e) {
            e.printStackTrace();
        }
        Authentication authentication = new PreAuthenticatedAuthenticationToken(a,null);

        System.out.println("22 authentication = " + authentication);
        return getAuthenticationManager().authenticate(authentication);
    }

    /**
     * This method is called if authentication was successful. Method build token with JWT using
     * AccountCredentials class as subject. and add header to the response.
     *
     * @param req   Incoming request
     * @param res
     * @param chain
     * @param auth
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res, FilterChain chain, Authentication auth) throws IOException, ServletException {
        try {
            A a = (A)auth.getPrincipal();
            String token = JWT.buildToken(a);
            System.out.println("token = " + token);
            res.addHeader(Constants.HEADER_STRING, Constants.TOKEN_PREFIX + " " + token);
        } catch (UserDefinedException e) {
            e.printStackTrace();
        }
        /*try {
        } catch (UserDefinedException e) {
            e.printStackTrace();
        }*/
    }


}
