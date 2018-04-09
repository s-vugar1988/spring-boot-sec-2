package boot.domain.exceptions;

/**
 * Created by SuleymanovVA on 5/19/2017.
 */
public class AuthenticationException extends UserDefinedException{

    public AuthenticationException(){
        super(20501, "UnAuth");
    }
}
