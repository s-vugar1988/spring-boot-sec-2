package boot.auth;

import boot.domain.A;
import boot.domain.AccountCredentials;
import boot.domain.exceptions.AuthenticationException;
import boot.util.Constants;
import boot.util.JWT;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.filter.GenericFilterBean;
import sun.text.resources.CollationData;
import sun.text.resources.sk.CollationData_sk;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Collections;

/**
 * Filter for checking requests token.
 *
 */
public class JWTAuthenticationFilter extends GenericFilterBean {

    /**
     * Method for
     * @param request
     * @param response
     * @param filterChain
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        try {

            System.out.println("33");
            //Convert ServletRequest to the HttpServletRequest
            HttpServletRequest httpRequest = (HttpServletRequest)request;
            //Read token from request header.
            String token = httpRequest.getHeader(Constants.HEADER_STRING );

            // remove token prefix and check token
            A a = JWT.checkToken4User(token.replace(Constants.TOKEN_PREFIX, ""), A.class);
            Authentication authentication = new PreAuthenticatedAuthenticationToken(token, a, null);

            // no exceptions occurred add authentication info to context
            SecurityContextHolder.getContext().setAuthentication(authentication);

            filterChain.doFilter(request,response);
        } catch (AuthenticationException e) {
            // Token was invalid do nothing
            e.printStackTrace();
        }
    }
}
