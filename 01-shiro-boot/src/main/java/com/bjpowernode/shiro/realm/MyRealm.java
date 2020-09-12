package com.bjpowernode.shiro.realm;

import org.apache.shiro.authc.*;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

/**
 * 自定义MyRealm用来实现用户的认证和授权
 * 父类AuthenticatingRealm 只用于用户认证（登陆）
 */
public class MyRealm extends AuthorizingRealm {


    /**
     * 用户认证的方法，不能手动调用，shiro会自动调用
     * @param authenticationToken 用户身份，这里放着用户名和密码
     * @return 用户登陆成功后的身份证明
     * @throws AuthenticationException 如果认证失败Shiro会抛出各种各样的异常
     * 常用异常：
     * UnknownAccountException 账号不存在
     * AccountException        账号异常
     * LockedAccountException  账号锁定
     * IncorrectCredentialsException 密码认证失败会shiro自动抛出异常表示密码错误
     * 注意：
     *     如果这些异常不够用可以自定义异常类并继承shiro认证异常父类 AuthenticationException
     *
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
        //获取页面中传递的用户账号
        String username = token.getUsername();

        //获取页面中的用户密码实际工作中基本不需要获取
        String password = new String(token.getPassword());

        //System.out.println(username+" -------- "+password);


        /**
          认证账号，这里应该从数据库中获取数据
         * 如果进入if表示账号不存在，要抛出异常
         */
        if(!"admin".equals(username)&&!"zhangsan".equals(username)&&!"user".equals(username)){
            //抛出账号错误的异常
            throw new UnknownAccountException();
        }
        /**
         * 认证账号，这里应该根据从数据库中获取来的数据进行逻辑判断，判断当前账号是否可用
         * IP是否允许等等，根据不同的逻辑可以抛出不同的异常
         */
        if("zhangsan".equals(username)){
            //抛出账号锁定异常
            throw new LockedAccountException();
        }
        //设置让当前用户登陆的密码进行加密,前端页面传过来的密码加密操作
        HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher();
        credentialsMatcher.setHashAlgorithmName("md5");
        credentialsMatcher.setHashIterations(2);
        this.setCredentialsMatcher(credentialsMatcher);

        //对数据库中的密码进行加密
        Object obj = new SimpleHash("md5","123456","",2);

        /**
         * 创建密码认证对象，由shiro自动认证密码
         * 参数1： 数据库中的账号（或者页面账号均可）
         * 参数2： 数据库中读取出来的密码
         * 参数3： 为当前Realm的名字
         * 如果密码认证成功则返回一个用户身份对象，如果密码认证失败Shiro会抛出异常IncorrectCredentialsException
         */
        return new SimpleAuthenticationInfo(username,obj,this.getName());
    }


    /**
     * 用户授权的方法，用户认证通过每次访问需要授权的请求时都需要执行这段代码来完成授权操作
     * 这里应该查询数据库来获取当前用户的所有角色和权限，并设置到shiro中
     * @param principalCollection
     * @return
     * 注意：由于每次点击需要授权的请求时，Shiro都会执行这个方法，因此如果这里的数据时来自于数据库中的
     *      那么一定要控制好不能每次都从数据库中获取数据这样效率太低了
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        System.out.println("进入授权方法！！！");
        //获取用户账号，根据账号在数据库查用户身份
        Object username = principalCollection.getPrimaryPrincipal();
        System.out.println("用户身份："+username);

        //设置角色这里模仿数据库用户身份集合，这个集合应该来自数据库
        Set<String> roles = new HashSet<>();
        if("admin".equals(username)){
            roles.add("admin");
            roles.add("user");
        }else if ("user".equals(username)) {
            roles.add("user");
        }

        Set<String>permissions=new HashSet<>();
        //设置权限，这里个操作应该是用数据中读取数据
        if("admin".equals(username)){
            //添加一个权限admin:add 只是一种命名风格表示admin下的add功能
            permissions.add("admin:add");
        }

        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.setRoles(roles);
        info.setStringPermissions(permissions);
        return info;
    }


    /**
     * 此处就是演示一下加密算法
     * @param args
     */
    public static void main(String[] args) {
        //密码加密码
        //参数 1 为加密算法 我们选择MD5加密
        //参数 2 为被加密的数据的数据
        //参数 3 为加密时的盐值 ，用于改变加密后数据结果
        //      通常这个盐值需要选择一个表中唯一的数据例如表中的账号
        //参数 4 为需要对数据使用指定的算法加密多少次
        Object obj1 = new SimpleHash("md5","123456","admin",1);
        System.out.println("使用md5加密一次"+obj1);

        Object obj2 = new SimpleHash("md5","123456","admin",2);
        System.out.println("使用md5加密两次"+obj2);

        Object obj3 = new SimpleHash("md5","a66abb5684c45962d887564f08346e8d","admin",1);
        System.out.println("使用md5分开加密两次"+obj3);

    }


}
