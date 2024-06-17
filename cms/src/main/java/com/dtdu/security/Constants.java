package com.dtdu.security;

import java.util.Arrays;
import java.util.List;

public class Constants {
    public static final String ADMIN_GROUP_NAME = "admin";
    public static final String TESTER_GROUP_NAME = "tester";
    public static final String ADMIN_ROLE_NAME = "admin";
    public static final String TESTER_ROLE_NAME = "tester";
    public static final String EVERYBODY_GROUP_NAME = "everybody";
    public static final List<String> TESTER_ROLES = Arrays.asList("xm.default-user.system-admin");

    public static final String HIPPO_SYS_SECURITY_PROVIDER = "hipposys:securityprovider";
    public static final String HIPPO_SYS_ACTIVE = "hipposys:active";
    public static final String HIPPO_SYS_FIRSTNAME = "hipposys:firstname";
    public static final String HIPPO_SYS_LASTNAME = "hipposys:lastname";
    public static final String HIPPO_SYS_EMAIL = "hipposys:email";
    public static final String HIPPO_SYS_MEMBERS = "hipposys:members";
    public static final String HIPPO_SYS_USERROLES = "hipposys:userroles";

    public static final String PROVIDER_INTERNAL = "internal";
    public static final String PROVIDER_SAML = "saml";

    public static final String ATTRIBUTE_FIRST_NAME = "firstname";
    public static final String ATTRIBUTE_LAST_NAME = "lastname";
    public static final String ATTRIBUTE_ROLE = "role";
    public static final String ATTRIBUTE_EMAIL = "email";

    public static final String SCHEMA_FIRST_NAME = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname";
    public static final String SCHEMA_LAST_NAME = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname";
    public static final String SCHEMA_EMAIL = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
    public static final String SCHEMA_ROLE = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";

    public static final int HOURS_ALLOWED_FROM_PREVIOUS_LOGIN = 168; // 7 DAYS
}
