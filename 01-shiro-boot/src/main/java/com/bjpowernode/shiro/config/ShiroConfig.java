package com.bjpowernode.shiro.config;

import com.bjpowernode.shiro.realm.MyRealm;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.apache.shiro.realm.Realm;

import java.util.LinkedHashMap;
import java.util.Map;
//spring配置类

@Configuration
public class ShiroConfig {
    /*
    * 配置一个安全管理器
    * */
    @Bean
    public SecurityManager securityManager(Realm myRealm){
        DefaultWebSecurityManager defaultWebSecurityManager = new DefaultWebSecurityManager();
        defaultWebSecurityManager.setRealm(myRealm);
        return defaultWebSecurityManager;
    }

    @Bean
    public MyRealm myRealm(){
        MyRealm myRealm =new MyRealm();
        return myRealm;
    }
    //配置一个Shiro的过滤器bean，这个bean将配置Shiro相关的一个规则的拦截
    //例如什么样的请求可以访问什么样的请求不可以访问等等
    @Bean
    public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager){
        //创建过滤器配置bean
        ShiroFilterFactoryBean shiroFilter = new ShiroFilterFactoryBean();
        shiroFilter.setSecurityManager(securityManager);

        //用于设置一个登录的请求地址，这个地址可以是一个html或jsp的访问路径，也可以是一个控制器的路径
        //作用是用于通知Shiro我们可以使用这里路径转向到登录页面，但Shiro判断到我们当前的用户没有登录时就会自动转换到这个路径
        //要求用户完成成功
        shiroFilter.setLoginUrl("/");//没有登陆往此处跳转


        //登录成功后转向页面，由于用户的登录后期需要交给Shiro完成，因此就需要通知Shiro登录成功之后返回到那个位置
        shiroFilter.setSuccessUrl("/success");//登陆成功往此处跳转


        //用于指定没有权限的页面，当用户访问某个功能是如果Shiro判断这个用户没有对应的操作权限，那么Shiro就会将请求
        //用shiro注解后，好像这个不用也行（Nathaniel's guess）
        //shiroFilter.setUnauthorizedUrl("/noPermission");//没有权限访问这个页面跳转到这里


        /**
         * 权限拦截规则
         */
        Map<String,String> filterChainMap=new LinkedHashMap<String,String>();
        //  /login 表示某个请求的名字    anon 表示可以使用游客什么进行登录（这个请求不需要登录）
        filterChainMap.put("/login","anon");
        //我们可以在这里配置所有的权限规则这列数据真正是需要从数据库中读取出来
        //或者在控制器中添加Shiro的注解
        //  /admin/**  表示一个请求名字的通配， 以admin开头的任意子孙路径下的所有请求
        //  authc 表示这个请求需要进行认证（登录），只有认证（登录）通过才能访问
        // 注意： ** 表示任意子孙路径
        //       *  表示任意的一个路径
        //       ? 表示 任意的一个字符

        //表示进入admin这个页面以及子页面，需要有admin的角色才可以
        //filterChainMap.put("/admin/**","authc,roles[admin]");
        //filterChainMap.put("/user/**","authc,roles[user]");
        //如果没有指定/** 那么如果某个请求不符合上面的拦截规则Shiro将放行这个请求
        //表示所有的请求路径全部都需要被拦截登录，这个必须必须写在Map集合的最后面,这个选项是可选的
        filterChainMap.put("/**","authc");
        shiroFilter.setFilterChainDefinitionMap(filterChainMap);
        return shiroFilter;
    }




    /*--------------以下的方法是用到shiro注解方法才用到的，注意上方的拦截链接是被注释掉了的！！！！！---------------------------*/
    /**
     * 开启Shiro注解支持（例如@RequiresRoles()和@RequiresPermissions()）
     * shiro的注解需要借助Spring的AOP来实现
     * @return
     */
    @Bean
    public DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator(){
        DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator=new DefaultAdvisorAutoProxyCreator();
        advisorAutoProxyCreator.setProxyTargetClass(true);
        return advisorAutoProxyCreator;
    }

    /**
     * 开启AOP的支持
     * @return
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager){
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor=new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }
}
