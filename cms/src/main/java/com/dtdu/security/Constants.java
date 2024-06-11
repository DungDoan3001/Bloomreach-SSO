package com.dtdu.security;

import java.util.Arrays;
import java.util.List;

public class Constants {
    public static final String ADMIN_GROUP_NAME = "admin";
    public static final String TESTER_GROUP_NAME = "tester";
    public static final String READER_GROUP_NAME = "reader";
    public static final String EVERYBODY_GROUP_NAME = "reader";
    public static final List<String> TESTER_ROLES = Arrays.asList("xm.default-user.system-admin");
    public static final List<String> READER_ROLES = Arrays.asList("xm.cms.user", "xm.console.user", "xm.dashboard.user", "xm.channel.user", "xm.content.user", "xm.system.user", "xm.security.viewer");

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
}
