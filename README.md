# Spring Security使用示例

Spring Security是基于JavaEE标准中的Filter实现的。
Spring Security的源码是Spring全家桶中最复杂的之一。推荐学习网站www.spring4all.com
Spring Security包括认证与授权部分。
## 使用方法

导入依赖包后Spring Security直接接管了整个系统的认证，自带了登录页面和自动生成了一个账号密码。
需要修改三个地方配置Spring Security：
    -User对象实现UserDetails接口；
    -UserService实现UserDetailsService接口；
    -新建一个配置类（带@Configuration注解）继承WebSecurityConfigurerAdapter类，重写三个参数不同的configure方法。

## 1.User对象实现UserDetails接口

主要是实现getAuthorities方法返回User的权限标识。
关于User权限标识的手段，复杂的有用户表+角色表+权限表；简单的使用加个type成员标记即可。

## 2.UserService实现UserDetailsService接口
实现loadUserByUsername方法即可，非常简单。

## 3.新建一个配置类继承WebSecurityConfigurerAdapter类，重写三个configure方法

这里涉及较多Spring Security的组件概念，比较容易搞乱。
三个configure方法：
    -configure(WebSecurity web)用于配置不过滤静态资源访问；
    -configure(AuthenticationManagerBuilder auth)实现自定义的认证逻辑;
    -configure(HttpSecurity http)定义http请求的认证行为，定义授权，remember-me和增加自定义Filter。

*Spring Security认证成功后,认证结果会通过SecurityContextHolder存入SecurityContext中。
在程序的其他地方可以通过SecurityContextHolder类获取User对象。*
