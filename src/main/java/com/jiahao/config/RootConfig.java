package com.jiahao.config;

import com.alibaba.druid.pool.DruidDataSource;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.swing.plaf.basic.ComboPopup;
import java.util.HashMap;
import java.util.Map;

/**
 * shiro的配置类,用户替代shiro的xml配置
 */
@Configuration
public class RootConfig {

    /**
     * 相当于在springmvc中配置
     * <bean id="shiroFilter" class="org.apache.shiro.spring.web.ShiroFilterFactoryBean">
     *         <property name="securityManager" ref="securityManager"/>
     *                 <property name="loginUrl" value="index"/>
     *                 <property name="filterChainDefinitions">
     *                     <value>
     *                         /index.jsp = anon  anon允许匿名访问，也就是允许不认证就能访问 -->
     *                         /logout = logout   安全退出后，logout拦截器会自动跳转到index.jsp -->
     *                         /** = authc
     *                     </value>
     *                 </property>
     *    </bean>
     *    方法返回值：class="org.apache.shiro.spring.web.ShiroFilterFactoryBean"
     *    方法名：id="shiroFilter"
     * @return
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilter(){
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager());
        shiroFilterFactoryBean.setLoginUrl("/index.jsp");
        //设置没有权限跳去的页面
        shiroFilterFactoryBean.setUnauthorizedUrl("/noRen.jsp");
        /*
        配置访问权限
           用map存储
         */
        Map<String,String> map = new HashMap<>();
        map.put("/index.jsp","anon");
        map.put("/logout","logout");
        map.put("/users/login","anon");
        map.put("/cars.jsp","roles[guest]");
        map.put("/users.jsp","roles[admin]");
        map.put("/**","authc");
        shiroFilterFactoryBean.setFilterChainDefinitionMap(map);
        return shiroFilterFactoryBean;
    }

    /**
     * 设置安全管理器
     * 相当于
     *     <bean id="securityManager" class="org.apache.shiro.web.mgt.DefaultWebSecurityManager">
     *         <property name="realm" ref="realm"></property>
     *         <property name="cacheManager" ref="cacheManager"/>
     *     </bean>
     */
    @Bean
    public DefaultWebSecurityManager securityManager(){
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(realm());
        securityManager.setCacheManager(cacheManager());
        return securityManager;
    }

    /**
     * 配置缓存
     *     <bean id="cacheManager" class="org.apache.shiro.cache.ehcache.EhCacheManager">
     *         <property name="cacheManagerConfigFile" value="classpath:each_shiro.xml"/>
     *     </bean>
     */
    @Bean
    public EhCacheManager cacheManager(){
        EhCacheManager manager = new EhCacheManager();
        manager.setCacheManagerConfigFile("classpath:each_shiro.xml");
        return manager;
    }

    /**
     * 设置jdbcrealm
     * 相当于
     *<bean id="realm" class="org.apache.shiro.realm.jdbc.JdbcRealm">
     *         <property name="dataSource" ref="dataSource"/>
     *         <property name="permissionsQuery" value="select pname from roles_permissions rp join roles r on rp.rid = r.rid join permissions p on rp.pid = p.pid where rname = ?"/>
     *         <property name="authenticationQuery" value="select password, salt from users where username = ?"/>
     *         <property name="userRolesQuery" value="select rname from users_roles ur join users u on ur.uid = u.uid join roles r on ur.rid = r.rid where username = ?"/>
     *         <property name="permissionsLookupEnabled" value="true"/>
     *         <property name="saltStyle" value="COLUMN"/>
     *         <property name="credentialsMatcher" ref="credentialsMatcher"/>
     *         <property name="cachingEnabled" value="true"/>
     *     </bean>
     */
    @Bean
    public JdbcRealm realm(){
        JdbcRealm realm = new JdbcRealm();
        realm.setDataSource(dataSource());
        realm.setPermissionsQuery("select pname from roles_permissions rp join roles r on rp.rid = r.rid join permissions p on rp.pid = p.pid where rname = ?");
        realm.setUserRolesQuery("select rname from users_roles ur join users u on ur.uid = u.uid join roles r on ur.rid = r.rid where username = ?");
        realm.setAuthenticationQuery("select password from users where username = ?");
//        realm.setSaltStyle(JdbcRealm.SaltStyle.COLUMN);
//        realm.setCredentialsMatcher(matcher());
        realm.setCachingEnabled(true);
        realm.setPermissionsLookupEnabled(true);
        return realm;
    }

    @Bean
    public HashedCredentialsMatcher matcher(){
        HashedCredentialsMatcher matcher = new HashedCredentialsMatcher();
        matcher.setHashAlgorithmName("md5");
        matcher.setHashIterations(1024);
        return matcher;
    }
    /**
     * 配置数据源
     * 相当于
     *     <bean id="dataSource" class="com.mchange.v2.c3p0.ComboPooledDataSource">
     *         <property name="driverClass" value="com.mysql.jdbc.Driver"/>
     *         <property name="jdbcUrl" value="jdbc:mysql://localhost:3306/shiro?characterEncoding"/>
     *         <property name="user" value="root"/>
     *         <property name="password" value="root"/>
     *     </bean>
     */
    @Bean
    //这里使用的数据源为druiddatasource
    public DruidDataSource dataSource(){
        DruidDataSource dataSource = new DruidDataSource();
        dataSource.setDriverClassName("com.mysql.jdbc.Driver");
        dataSource.setUrl("jdbc:mysql://localhost:3306/shiro?characterEncoding");
        dataSource.setUsername("root");
        dataSource.setPassword("root");
        return dataSource;
    }

    /**
     * 要使用shiro的注解，需在配置类中加入如下的bean
     * @return
     */
    @Bean
    @ConditionalOnMissingBean
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator defaultAAP = new DefaultAdvisorAutoProxyCreator();
        defaultAAP.setProxyTargetClass(true);
        return defaultAAP;
    }
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor() {
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager());
        return authorizationAttributeSourceAdvisor;
    }
}
