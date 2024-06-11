package com.dtdu.security;

import org.apache.commons.lang.*;
import org.apache.jackrabbit.api.security.user.*;
import org.apache.jackrabbit.value.*;
import org.hippoecm.repository.security.*;
import org.hippoecm.repository.security.user.*;
import org.slf4j.*;

import java.util.*;
import javax.jcr.*;

import static com.dtdu.security.Constants.*;

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
                if (validateAuthentication(simpleCredentials)) {
                    handleUserInformation(simpleCredentials);
                    return true;
                } else {
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
        String currentRole = (String) credentials.getAttribute(ATTRIBUTE_ROLE);
        if(currentRole == null || currentRole.trim().isEmpty())
            currentRole = READER_GROUP_NAME;

        Node user = userManager.hasUser(userId) ? userManager.getUser(userId) : userManager.createUser(userId);

        Node group = manageGroup(currentRole);
        syncUser(user, credentials);
        syncGroup(user, group);
    }

    private Node manageGroup(String role) throws RepositoryException {
        String groupName = getGroupNameForRole(role);

        // NEED TO CHECK FOR ADMIN ROLE SINCE IT DOES NOT NEED TO BE CREATED.
        if(!groupName.equals(ADMIN_GROUP_NAME)) {
            List<String> groupRoles;
            switch (groupName) {
                case TESTER_GROUP_NAME:
                    groupRoles = TESTER_ROLES;
                    break;
                default:
                    groupRoles = READER_ROLES;
                    break;
            }
            return getGroupManager().hasGroup(groupName) ? getGroupManager().getGroup(groupName) : createNewGroup(groupName, groupRoles);
        } else {
            return getGroupManager().getGroup(ADMIN_GROUP_NAME);
        }
    }

    private String getGroupNameForRole(String role) {
        switch (role) {
            case ADMIN_GROUP_NAME:
                return ADMIN_GROUP_NAME;
            case TESTER_GROUP_NAME:
                return TESTER_GROUP_NAME;
            default:
                return READER_GROUP_NAME;
        }
    }

    private void syncUser(final Node user, final SimpleCredentials credentials) throws RepositoryException {
        try {
            user.setProperty(HIPPO_SYS_SECURITY_PROVIDER, PROVIDER_SAML);
            user.setProperty(HIPPO_SYS_ACTIVE, true);
            user.setProperty(HIPPO_SYS_FIRSTNAME, (String) credentials.getAttribute(ATTRIBUTE_FIRST_NAME));
            user.setProperty(HIPPO_SYS_LASTNAME, (String) credentials.getAttribute(ATTRIBUTE_LAST_NAME));
            user.setProperty(HIPPO_SYS_EMAIL, (String) credentials.getAttribute(ATTRIBUTE_EMAIL));

            user.getSession().save();
        } catch (RepositoryException e) {
            throw new RepositoryException("Failed to sync user properties: ", e);
        }
    }

    private void syncGroup(final Node user, final Node group) throws RepositoryException {
        final String newMember = user.getName();
        Set<String> members = getGroupManager().getMembers(group);

        if (!members.contains(newMember)) {
            Value[] memberList = group.getProperties(HIPPO_SYS_MEMBERS).nextProperty().getValues();
            Value[] newMemberList = Arrays.copyOf(memberList, memberList.length + 1);
            newMemberList[memberList.length] = new StringValue(user.getName());
            group.setProperty(HIPPO_SYS_MEMBERS, newMemberList);
            group.getSession().save();
        }

        NodeIterator groupsThatMemberBelongsTo = getGroupManager().getMemberships(newMember);
        while (groupsThatMemberBelongsTo.hasNext()) {
            Node groupNode = groupsThatMemberBelongsTo.nextNode();
            log.info("Current group: " + groupNode.getName());

            if (!(groupNode.getName().equals(group.getName()) || groupNode.getName().equals(EVERYBODY_GROUP_NAME))) {
                // Get the current members
                Value[] currentMembers = groupNode.getProperty(HIPPO_SYS_MEMBERS).getValues();
                List<Value> updatedMembers = new ArrayList<>();

                // Check each member and add to list if not the member to remove
                for (Value member : currentMembers) {
                    if (!member.getString().equals(newMember)) {
                        updatedMembers.add(member);
                    }
                }

                // Convert updated list back to array and set the property
                if (updatedMembers.size() != currentMembers.length) {
                    Value[] newMembers = updatedMembers.toArray(new Value[0]);
                    groupNode.setProperty(HIPPO_SYS_MEMBERS, newMembers);
                    groupNode.getSession().save(); // Save the session changes
                }
            }
        }
    }

    private Node createNewGroup(final String groupName, final List<String> roleList) throws RepositoryException {
        try {
            Node group = getGroupManager().createGroup(groupName);
            group.setProperty(HIPPO_SYS_SECURITY_PROVIDER, new StringValue(PROVIDER_INTERNAL));

            Value[] values = roleList.stream()
                    .map(StringValue::new)
                    .toArray(Value[]::new);

            group.setProperty(HIPPO_SYS_USERROLES, values);
            group.getSession().save();

            return group;
        } catch (RepositoryException e) {
            throw new RepositoryException("Failed to create new group: ", e);
        }
    }
}