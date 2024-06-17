package com.dtdu.security;

import org.hippoecm.frontend.model.UserCredentials;
import org.opensaml.saml2.core.Attribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SAMLCredential;

import javax.jcr.SimpleCredentials;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.dtdu.security.Constants.*;

public class LoginSuccessFilter implements Filter {
    private static final Logger logger = LoggerFactory.getLogger( LoginSuccessFilter.class );
    private static final String SSO_USER_STATE = SSOUserState.class.getName();

    private static ThreadLocal<SSOUserState> tlCurrentSSOUserState = new ThreadLocal<SSOUserState>();

    @Override
    public void init(FilterConfig filterConfig) {
    }

    /**
     * Creates a new secured session if the user is authorized. {@inheritDoc}
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        logger.info("doFilter LoginSuccessFilter");

        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (!authentication.isAuthenticated()){
            logger.info("User not authenticated");
            chain.doFilter(request, response);
            return;
        }

        // Check if the user already has a SSO user state stored in HttpSession before.
        final HttpSession session = ((HttpServletRequest) request).getSession();
        SSOUserState userState = (SSOUserState) session.getAttribute(SSO_USER_STATE);

        if(userState == null || !userState.getSessionId().equals(session.getId())) {
            if(authentication.getCredentials() instanceof SAMLCredential) {
                final SAMLCredential samlCredential = (SAMLCredential) authentication.getCredentials();
                if(samlCredential.getNameID() != null) {
                    userState = new SSOUserState(new UserCredentials(createSimpleCredentials(samlCredential)), session.getId());
                    session.setAttribute(SSO_USER_STATE, userState);
                } else {
                    logger.warn("nameID is null in SAML credentials");
                    chain.doFilter(request, response);
                    return;
                }
            } else {
                logger.debug("Authenticated user credentials are not SAML credentials");
                chain.doFilter(request,response);
                return;
            }
        }

        // If the user has a valid SSO user state, then
        // set a JCR Credentials as request attribute (named by FQCN of UserCredentials class).
        // Then the CMS application will use the JCR credentials passed through this request attribute.
        if (userState.getSessionId().equals(session.getId())) {
            request.setAttribute(UserCredentials.class.getName(), userState.getCredentials());
        }

        try {
            tlCurrentSSOUserState.set(userState);
            chain.doFilter(request, response);
        } finally {
            tlCurrentSSOUserState.remove();
        }

    }

    /**
     * Get current <code>SSOUserState</code> instance from the current thread local context.
     * @return
     */
    static SSOUserState getCurrentSSOUserState() {
        return tlCurrentSSOUserState.get();
    }

    @Override
    public void destroy() {
        tlCurrentSSOUserState.remove();
    }

    private SimpleCredentials createSimpleCredentials(final SAMLCredential credential) {
        final String username = credential.getNameID().getValue();
        final SimpleCredentials simpleCredentials = new SimpleCredentials(username, "DUMMY_PWD".toCharArray());

        for(Attribute attr : credential.getAttributes()) {
            String[] attrVals = credential.getAttributeAsStringArray(attr.getName());
            List<String> values = new ArrayList<String>(Arrays.asList(attrVals));
            logger.info(String.format("[CLAIMS INFO]:    %s (%s) : %s", attr.getName(), attr.getFriendlyName(), values));
        }

        simpleCredentials.setAttribute(ATTRIBUTE_FIRST_NAME, credential.getAttributeAsString(SCHEMA_FIRST_NAME));
        simpleCredentials.setAttribute(ATTRIBUTE_LAST_NAME, credential.getAttributeAsString(SCHEMA_LAST_NAME));
        simpleCredentials.setAttribute(ATTRIBUTE_EMAIL, credential.getAttributeAsString(SCHEMA_EMAIL));
        simpleCredentials.setAttribute(ATTRIBUTE_ROLE, credential.getAttributeAsString(SCHEMA_ROLE));
        simpleCredentials.setAttribute(SSOUserState.SAML_ID, username);

        return simpleCredentials;
    }
}
