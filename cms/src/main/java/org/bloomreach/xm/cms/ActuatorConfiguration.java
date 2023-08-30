package org.bloomreach.xm.cms;

import javax.naming.NamingException;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.actuate.jdbc.DataSourceHealthIndicator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.jndi.JndiObjectFactoryBean;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;

@Configuration
@PropertySource(value = "classpath:actuator.properties")
// from 15.3.0 onwards, add this security annotation
@EnableWebSecurity
public class ActuatorConfiguration {

    @Value("${app.datasource.name}")
    String datasourceName;

    @Bean(destroyMethod = "")
    DataSource jndiDataSource() throws IllegalArgumentException, NamingException {
        final JndiObjectFactoryBean bean = new JndiObjectFactoryBean();
        bean.setJndiName("java:comp/env/jdbc/" + datasourceName);
        bean.afterPropertiesSet();
        return (DataSource) bean.getObject();
    }

    @Bean
    HealthIndicator dbHealthIndicator(final DataSource dataSource) {
        return new DataSourceHealthIndicator(dataSource, "SELECT 1");
    }

    // Note: with Spring Boot 2.7, there's tighter security by default so
    // from 15.3.0 onwards, add this method
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        // allow all requests, please adjust if applicable
        return (web) -> web.ignoring().antMatchers("/**");
    }
}
