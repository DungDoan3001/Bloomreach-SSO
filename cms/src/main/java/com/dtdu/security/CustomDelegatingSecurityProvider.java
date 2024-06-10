package com.dtdu.security;

import org.apache.commons.lang.*;
import org.apache.jackrabbit.api.security.user.*;
import org.apache.jackrabbit.value.*;
import org.hippoecm.repository.security.*;
import org.hippoecm.repository.security.user.*;
import org.slf4j.*;
import java.util.*;
import javax.jcr.*;

import static com.dtdu.security.LoginSuccessFilter.*;

public class CustomDelegatingSecurityProvider extends DelegatingSecurityProvider {
    private static Logger log = LoggerFactory.getLogger(CustomDelegatingSecurityProvider.class);
    private HippoUserManager userManager;

    public CustomDelegatingSecurityProvider() throws RepositoryException {
        super(new RepositorySecurityProvider());
    }

    @Override
    public UserManager getUserManager() throws RepositoryException {
        if (userManager == null) {
            userManager = new DelegatingHippoUserManager((HippoUserManager) super.getUserManager()) {
                @Override
                public boolean authenticate(SimpleCredentials simpleCredentials) throws RepositoryException {
                    if (validateAuthentication(simpleCredentials)) {
                        handleUserInformation(simpleCredentials);
                        return true;
                    } else {
                        return false;
                    }
                }
            };
        }
        return userManager;
    }

    /**
     * Returns a custom (delegating) HippoUserManager to authenticate a user by SAML Assertion.
     */
    @Override
    public UserManager getUserManager(Session session) throws RepositoryException {
        return new DelegatingHippoUserManager((HippoUserManager) super.getUserManager(session)) {
            @Override
            public boolean authenticate(SimpleCredentials simpleCredentials) throws RepositoryException {
                if(validateAuthentication(simpleCredentials)) {
                    handleUserInformation(simpleCredentials);
                    return true;
                } else{
                    return false;
                }
            }
        };
    }

    /**
     * Validates SAML SSO Assertion.
     * <p>
     * In this example, simply invokes SAML API (<code>AssertionHolder#getAssertion()</code>) to validate.
     * </P>
     *
     * @param creds
     * @return
     * @throws RepositoryException
     */
    protected boolean validateAuthentication(SimpleCredentials creds) throws RepositoryException {
        log.info("CustomDelegatingSecurityProvider validating credentials: {}", creds);

        SSOUserState userState = LoginSuccessFilter.getCurrentSSOUserState();

        /*
         * If userState found in the current thread context, this authentication request came from
         * CMS application.
         * Otherwise, this authentication request came from SITE application (e.g, channel manager rest service).
         */

        if (userState != null) {

            // Asserting must have been done by the *AssertionValidationFilter* and the assertion thread local variable
            // must have been set by AssertionThreadLocalFilter already.
            // So, simply check if you have assertion object in the thread local.
            return StringUtils.isNotEmpty(userState.getCredentials().getUsername());

        } else {

            String samlId = (String) creds.getAttribute(SSOUserState.SAML_ID);

            if (StringUtils.isNotBlank(samlId)) {
                log.info("Authentication allowed to: {}", samlId);
                return true;
            }
        }

        return false;
    }

    private void handleUserInformation(final SimpleCredentials credentials) throws RepositoryException {
        String userId = credentials.getUserID();
        String currentRole = (String) credentials.getAttribute(ROLE_ATTRIBUTE);
        if (!userManager.hasUser(userId)) {
            log.info(credentials.getAttribute(ROLE_ATTRIBUTE) + " ROELEEEEEEEEE");
            Node user = userManager.createUser(userId);
            switch (currentRole) {
                case "admin":
                    syncUser(user, credentials);
                    syncGroup(user, getGroupManager().getGroup("admin"));
                    break;
                case "tester":
                    String testerGroupName = "tester";
                    List<String> testerRoles = Arrays.asList("xm.repository-browser.user", "xm.default-user.system-admin");
                    Node testerGroup = (getGroupManager().hasGroup(testerGroupName)) ? getGroupManager().getGroup(testerGroupName) : createNewGroup(testerGroupName, testerRoles);
                    syncUser(user, credentials);
                    syncGroup(user, testerGroup);
                default:
                    String readerGroupName = "reader";
                    List<String> readerRoles = Arrays.asList("xm.repository-browser.user", "xm.default-user.system-admin");
                    Node readerGroup = (getGroupManager().hasGroup(readerGroupName)) ? getGroupManager().getGroup(readerGroupName) : createNewGroup(readerGroupName, readerRoles);
                    syncUser(user, credentials);
                    syncGroup(user, readerGroup);
            }
        } else {
            Node user = userManager.getUser(userId);
            switch (currentRole) {
                case "admin":
                    syncUser(user, credentials);
                    syncGroup(user, getGroupManager().getGroup("admin"));
                    break;
                case "tester":
                    String testerGroupName = "tester";
                    List<String> testerRoles = Arrays.asList("xm.repository-browser.user", "xm.default-user.system-admin");
                    Node testerGroup = (getGroupManager().hasGroup(testerGroupName)) ? getGroupManager().getGroup(testerGroupName) : createNewGroup(testerGroupName, testerRoles);
                    syncUser(user, credentials);
                    syncGroup(user, testerGroup);
                default:
                    String readerGroupName = "reader";
                    List<String> readerRoles = Arrays.asList("xm.repository-browser.user", "xm.default-user.system-admin");
                    Node readerGroup = (getGroupManager().hasGroup(readerGroupName)) ? getGroupManager().getGroup(readerGroupName) : createNewGroup(readerGroupName, readerRoles);
                    syncUser(user, credentials);
                    syncGroup(user, readerGroup);
            }
        }
    }

    private void syncUser(final Node user, final SimpleCredentials credentials) throws RepositoryException {
        user.setProperty("hipposys:securityprovider", "saml");
        user.setProperty("hipposys:active", true);
        user.setProperty("hipposys:firstname", (String) credentials.getAttribute(FIRST_NAME_ATTRIBUTE));
        user.setProperty("hipposys:lastname", (String) credentials.getAttribute(LASTNAME_ATTRIBUTE));
        user.setProperty("hipposys:email", (String) credentials.getAttribute(EMAIL_ATTRIBUTE));
    }

    private void syncGroup(final Node user, final Node group) throws RepositoryException {
        final String newMember = user.getName();
        Set<String> members = getGroupManager().getMembers(group);

        Boolean foundMember = false;
        for (String member : members) {
            if(member.equals(newMember)) {
                foundMember = true;
                break;
            }
        }

        if(!foundMember) {
            Value[] membersList = group.getProperties("hipposys:members").nextProperty().getValues();
            Value[] newMemberList = Arrays.copyOf(membersList, membersList.length + 1);
            newMemberList[membersList.length] = new StringValue(user.getName());
            group.setProperty("hipposys:members", newMemberList);
        }

        NodeIterator groupsThatMemberBelongsTo = getGroupManager().getMemberships(newMember);
        Node groupNode = groupsThatMemberBelongsTo.nextNode();
        while(groupNode != null) {
            log.info("Current group: " + groupNode.getName());
            groupNode = groupsThatMemberBelongsTo.nextNode();
        }
    }

    private Node createNewGroup(final String groupName, final List<String> roleList) throws RepositoryException {
        Node group = getGroupManager().createGroup(groupName);
        group.setProperty("hipposys:securityprovider", new StringValue("internal"));

        final Value[] values = new Value[roleList.size()];
        for (int index = 0; index < roleList.size(); index++) {
            values[index] = group.getSession().getValueFactory().createValue(roleList.get(index));
            log.info("VALUE INDEX OF [" + index + "]: " + values[index]);
        }
        group.setProperty("hipposys:userroles", values);
        return group;
    }
}