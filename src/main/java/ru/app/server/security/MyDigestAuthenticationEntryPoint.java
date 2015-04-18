package ru.app.server.security;

import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.codec.Base64;

import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.NonceExpiredException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author p.pavlovsky
 * @version $Revision$
 *          EntryPoint for not digest authentication user
 */
public class MyDigestAuthenticationEntryPoint extends DigestAuthenticationEntryPoint {

    /**
     * Json Response for user
     *
     * @param request       request
     * @param response      response
     * @param authException authException
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // compute a nonce (do not use remote IP address due to proxy farms)
        // format of nonce is:
        //   base64(expirationTime + ":" + md5Hex(expirationTime + ":" + key))
        long expiryTime = System.currentTimeMillis() + (getNonceValiditySeconds() * 1000);
        String signatureValue = md5Hex(expiryTime + ":" + getKey());
        String nonceValue = expiryTime + ":" + signatureValue;
        String nonceValueBase64 = new String(Base64.encode(nonceValue.getBytes()));

        // qop is quality of protection, as defined by RFC 2617.
        // we do not use opaque due to IE violation of RFC 2617 in not
        // representing opaque on subsequent requests in same session.
        String authenticateHeader = "Digest realm=\"" + getRealmName() + "\", " + "qop=\"auth\", nonce=\""
                + nonceValueBase64 + "\"";

        if (authException instanceof NonceExpiredException) {
            authenticateHeader = authenticateHeader + ", stale=\"true\"";
        }


        httpResponse.addHeader("WWW-Authenticate", authenticateHeader);

        ObjectMapper mapper = new ObjectMapper();
        Map<String, String> result = new HashMap<String, String>();
        result.put("message", "Access denied");
        String resultMessage = mapper.writeValueAsString(result);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        PrintWriter out = response.getWriter();
        out.print(resultMessage);
        out.close();

    }


    static String md5Hex(String data) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("No MD5 algorithm available!");
        }

        return new String(Hex.encode(digest.digest(data.getBytes())));
    }
}
