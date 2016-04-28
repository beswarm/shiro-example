package com.github.zhangkaitao.shiro.chapter2;

import junit.framework.Assert;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.authz.ModularRealmAuthorizer;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SessionsSecurityManager;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Destroyable;
import org.apache.shiro.util.Factory;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import org.junit.Test;


/**
 * <p>User: Zhang Kaitao
 * <p>Date: 14-1-25
 * <p>Version: 1.0
 */

/**
 * 1,3,4 Realm中间都有 zhang 123的用户，但是2中间是wang 123的用户,登录的用户是 zhang 123
 */
public class AuthenticatorTest {

    /**
     [main]
     #指定securityManager的authenticator实现
     authenticator=org.apache.shiro.authc.pam.ModularRealmAuthenticator
     securityManager.authenticator=$authenticator

     #指定securityManager.authenticator的authenticationStrategy
     allSuccessfulStrategy=org.apache.shiro.authc.pam.AllSuccessfulStrategy
     securityManager.authenticator.authenticationStrategy=$allSuccessfulStrategy

     myRealm1=com.github.zhangkaitao.shiro.chapter2.realm.MyRealm1
     myRealm2=com.github.zhangkaitao.shiro.chapter2.realm.MyRealm2
     myRealm3=com.github.zhangkaitao.shiro.chapter2.realm.MyRealm3
     securityManager.realms=$myRealm1,$myRealm3
     */
    @Test
    public void testAllSuccessfulStrategyWithSuccess() {
        login("classpath:shiro-authenticator-all-success.ini");
        Subject subject = SecurityUtils.getSubject();

        //得到一个身份集合，其包含了Realm验证成功的身份信息
        PrincipalCollection principalCollection = subject.getPrincipals();
        Assert.assertEquals(2, principalCollection.asList().size());
    }

    /**
     [main]
     #指定securityManager的authenticator实现
     authenticator=org.apache.shiro.authc.pam.ModularRealmAuthenticator
     securityManager.authenticator=$authenticator

     #指定securityManager.authenticator的authenticationStrategy
     allSuccessfulStrategy=org.apache.shiro.authc.pam.AllSuccessfulStrategy
     securityManager.authenticator.authenticationStrategy=$allSuccessfulStrategy

     myRealm1=com.github.zhangkaitao.shiro.chapter2.realm.MyRealm1
     myRealm2=com.github.zhangkaitao.shiro.chapter2.realm.MyRealm2
     myRealm3=com.github.zhangkaitao.shiro.chapter2.realm.MyRealm3
     securityManager.realms=$myRealm1,$myRealm2
     */
    @Test(expected = UnknownAccountException.class)
    public void testAllSuccessfulStrategyWithFail() {
        login("classpath:shiro-authenticator-all-fail.ini");
    }


    /**
     [main]
     #指定securityManager的authenticator实现
     authenticator=org.apache.shiro.authc.pam.ModularRealmAuthenticator
     securityManager.authenticator=$authenticator

     #指定securityManager.authenticator的authenticationStrategy
     allSuccessfulStrategy=org.apache.shiro.authc.pam.AtLeastOneSuccessfulStrategy
     securityManager.authenticator.authenticationStrategy=$allSuccessfulStrategy

     myRealm1=com.github.zhangkaitao.shiro.chapter2.realm.MyRealm1
     myRealm2=com.github.zhangkaitao.shiro.chapter2.realm.MyRealm2
     myRealm3=com.github.zhangkaitao.shiro.chapter2.realm.MyRealm3
     securityManager.realms=$myRealm1,$myRealm2,$myRealm3
     */
    @Test
    public void testAtLeastOneSuccessfulStrategyWithSuccess() {
        login("classpath:shiro-authenticator-atLeastOne-success.ini");
        Subject subject = SecurityUtils.getSubject();

        //得到一个身份集合，其包含了Realm验证成功的身份信息
        PrincipalCollection principalCollection = subject.getPrincipals();
        Assert.assertEquals(2, principalCollection.asList().size());
    }


    /**
     [main]
     #指定securityManager的authenticator实现
     authenticator=org.apache.shiro.authc.pam.ModularRealmAuthenticator
     securityManager.authenticator=$authenticator

     #指定securityManager.authenticator的authenticationStrategy
     allSuccessfulStrategy=org.apache.shiro.authc.pam.FirstSuccessfulStrategy
     securityManager.authenticator.authenticationStrategy=$allSuccessfulStrategy

     myRealm1=com.github.zhangkaitao.shiro.chapter2.realm.MyRealm1
     myRealm2=com.github.zhangkaitao.shiro.chapter2.realm.MyRealm2
     myRealm3=com.github.zhangkaitao.shiro.chapter2.realm.MyRealm3
     securityManager.realms=$myRealm1,$myRealm2,$myRealm3
     */
    @Test
    public void testFirstOneSuccessfulStrategyWithSuccess() {
        login("classpath:shiro-authenticator-first-success.ini");
        Subject subject = SecurityUtils.getSubject();

        //得到一个身份集合，其包含了第一个Realm验证成功的身份信息
        PrincipalCollection principalCollection = subject.getPrincipals();
        Assert.assertEquals(1, principalCollection.asList().size());
    }

    @Test
    public void testAtLeastTwoStrategyWithSuccess() {
        login("classpath:shiro-authenticator-atLeastTwo-success.ini");
        Subject subject = SecurityUtils.getSubject();

        //得到一个身份集合，因为myRealm1和myRealm4返回的身份一样所以输出时只返回一个
        PrincipalCollection principalCollection = subject.getPrincipals();
        Assert.assertEquals(1, principalCollection.asList().size());
    }

    @Test
    public void testOnlyOneStrategyWithSuccess() {
        login("classpath:shiro-authenticator-onlyone-success.ini");
        Subject subject = SecurityUtils.getSubject();

        //得到一个身份集合，因为myRealm1和myRealm4返回的身份一样所以输出时只返回一个
        PrincipalCollection principalCollection = subject.getPrincipals();
        Assert.assertEquals(1, principalCollection.asList().size());
    }

    private void login(String configFile) {
        //1、获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager
        Factory<org.apache.shiro.mgt.SecurityManager> factory =
                new IniSecurityManagerFactory(configFile);

        //2、得到SecurityManager实例 并绑定给SecurityUtils
        org.apache.shiro.mgt.SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        //3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");

        subject.login(token);
    }

    @After
    public void tearDown() throws Exception {
        ThreadContext.unbindSubject();//退出时请解除绑定Subject到线程 否则对下次测试造成影响
    }

}
