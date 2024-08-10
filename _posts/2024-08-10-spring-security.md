---
layout: post
title: Spring Security
categories: Spring
tags: [Spring, Spring Security]
---

## 一、基本概念

### 1.认证

判断一个用户身份是否合法的过程，身份合法就可以访问系统资源，否则拒绝访问。

### 2.会话

认证通过后，会创建一个会话将认证的用户信息保存起来，目的是为了保持当前用户的登录状态。

#### 1.基于session方式

认证成功后，服务端把用户数据保存在session（当前会话）中，发给客户端session_id保存在cookie中，用户每次发出请求都会携带session_id，服务端判断请求是否有session_id校验用户，用户退出系统时或者session_id过期，客户端的session_id就无效了。

![](https://raw.githubusercontent.com/zwy-hub/assets/main/person-website/img/spring-security/session%E8%AE%A4%E8%AF%81.PNG)  

#### 2.基于token方式

认证成功后，服务端会生成一个token（令牌）给客户端，客户端可以保存在cookie或者localStorage等存储中（session方式只能放在cookie中），每次请求都带着token，服务端根据生成token的算法可以判断token的合法性。

![](https://raw.githubusercontent.com/zwy-hub/assets/main/person-website/img/spring-security/token%E8%AE%A4%E8%AF%81.PNG) 

### 3.授权

​用户认证通过后，根据用户身份，控制其所能访问的资源的权限的过程。

#### 1.基于角色授权

​访问某个资源时，根据角色的身份判断时候拥有访问的权限，比如总经理能查看工资表，当需求改变时，变为总经理和部门经理都可以查看工资表，那么代码就需要进行修改，影响系统的健壮性。

#### 2.基于资源授权

​访问某个资源时，根据用户是否具有某项权限标识，来控制其访问，比如总经理具有查看工资表的权限标识，所以可以访问。

## 二、基于session的认证方式

### 1.认证流程



### 2.流程



#### 1.认证

实现类中，判断用户身份信息

{% highlight java linenos %}

public User login(User user) {
    if (user == null && user.getUsername == null) {
        Assert.isTrue(user != null
                && StringUtils.isNotBlank(user.getUsername()) 
                && StringUtils.isNotBlank(user.getPassword()), "用户名或密码不能为空");
        // 登录操作
        ...
    }
}

{% endhighlight %}

#### 2.会话

身份验证成功，存放session

{% highlight java linenos %}

@RequestMapping("/login")
@ResponseBody
public UserDto login(User user,HttpSession session) {
    UserDto result = authenticationService.login(user);
    session.setAttribute(UserDto.USER_KEY,result);
    return result;
}

{% endhighlight %}

退出登录等，清除session

{% highlight java linenos %}
@RequestMapping("/logout")
@ResponseBody
public String logout(HttpSession session){
    session.invalidate();
    return "退出成功";
}
{% endhighlight %}

#### 3.授权

添加拦截器，请求之前进入拦截器，校验用户权限

{% highlight java linenos %}
@Component
public class ResourceInterceptor implements HandlerInterceptor {
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        Object o = request.getSession().getAttribute(UserDto.USER_KEY);
        if (o == null) {
            response.getWriter().println("please login");
            return false;
        }
        UserDto userDto = (UserDto) o;
        //获取用户权限，根据请求的url和权限对比
        String requestURI = request.getRequestURI();
        if (userDto.getAuthorities().contains("111") && requestURI.contains("/r1"))
            return true;
        if (userDto.getAuthorities().contains("222") && requestURI.contains("/r2"))
            return true;
        response.getWriter().println("no authority，access denied!!");
        return false;
    }
}
{% endhighlight %}

注册拦截器，添加需要拦截的请求路径

{% highlight java linenos %}
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Autowired
    private ResourceInterceptor resourceInterceptor;

    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(resourceInterceptor).addPathPatterns("/r/**");
    }
}
{% endhighlight %}

## 三、Spring Security

### 1.引入依赖

spring boot

{% highlight xml linenos %}
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
{% endhighlight %}

没有spring boot

{% highlight xml linenos %}
<dependencyManagement>
    <dependencies>
        <!-- ... other dependency elements ... -->
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-bom</artifactId>
            <version>{spring-security-version}</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependencies>
    <!-- ... other dependency elements ... -->
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-config</artifactId>
    </dependency>
</dependencies>
{% endhighlight %}

### 2.认证流程

​安全访问控制可以用FIlter或AOP来实现，Spring Security则是用**Filter**来实现的。Spring Security初始化的时候会有创建一个过滤器FilterChainProxy，它实现了javax.servlet.filter，

![](https://raw.githubusercontent.com/zwy-hub/assets/main/person-website/img/spring-security/%E8%AE%A4%E8%AF%81%E6%B5%81%E7%A8%8B.PNG)  

1.用户登录请求，得到username和password

2.将username和password封装在UsernamePasswordAuthenticationToken（authRequest）中，

3.把请求（authRequest）交给AuthenticationManager去执行接口里的authenticate()方法

4.由DaoAuthenticationProvider通过请求的username去找正确的账号密码（UserDetails）

5.真实用户信息查到了，再根据用户输入的密码和UserDetails中的密码进行比较，真实密码可能加密了（数据库中存储的密码加密了），通过密码编码器PasswordEncoder进行比较

6.密码正确，就把权限填充到UsernamePasswordAuthenticationToken中返回

7.将UsernamePasswordAuthenticationToken保存到安全上下文

{% highlight java linenos %}
//6
UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
//7
SecurityContextHolder.getContext().setAuthentication(authentication);
{% endhighlight %}

### 3.授权流程

​授权主要是根据**投票**进行授权，根据用户的权限authentication，和访问资源所需的权限configAttributes进行比较，投票具体实现是AccessDecisionManager接口，有三种投票规则（实现类），具体采用哪种投票规则可自己选择。

![](https://raw.githubusercontent.com/zwy-hub/assets/main/person-website/img/spring-security/%E6%8E%88%E6%9D%83%E6%B5%81%E7%A8%8B.PNG)  

1.默认投票规则AffirmativeBased

​只要用户拥有的权限，和资源所需的权限，有一个符合就赞成，获得授权。

2.ConsensusBased

​少数服从多数，如果赞成和反对相同票，就根据ConsensusBased类中的allowIfEqualGrantedDeniedDecisions参数的值是否为真来判断能不能授权，默认相等票能获得授权。

3.UnanimousBased

​与AffirmativeBased相反，有一个反对就没权访问，所以必须全票通过才能得到授权。

## 四、代码编写

### 1.认证

定义一个继承WebSecurityConfigurerAdapter的配置类SecurityConfig，能够实现对用户的认证

{% highlight java linenos %}
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserService userService;

    //查询用户信息，从数据库查询
    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
                //查询用户信息，从数据库查询
                User user = userService.findByUsername(s);
                if (user != null) {
                    return new AdminUserDetails(user);
                }
                throw new UsernameNotFoundException("用户名或密码错误");
            }
        };
    }
    //密码编码器
    @Bean
    public PasswordEncoder passwordEncoder() {
        //直接就是字符串，没有用到加密算法
//        return NoOpPasswordEncoder.getInstance();
        return new BCryptPasswordEncoder();
    }
    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService()).passwordEncoder(new BCryptPasswordEncoder());
    }
}
{% endhighlight %}

{% highlight java linenos %}
public class AdminUserDetails implements UserDetails {
    private User user;

    public AdminUserDetails(User user) {
        this.user = user;
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        //返回当前用户的权限
        return Arrays.asList(new SimpleGrantedAuthority(user.getRole()));
    }

    public String getPassword() {
        return user.getPassword();
    }

    public String getUsername() {
        return user.getUsername();
    }

    public boolean isAccountNonExpired() {
        return true;
    }

    public boolean isAccountNonLocked() {
        return true;
    }

    public boolean isCredentialsNonExpired() {
        return true;
    }

    public boolean isEnabled() {
        return true;
        //return user.getStatus() == 1;
    }
}
{% endhighlight %}

### 2.会话

通过SecurityContextHolder.getContext().getAuthentication()将身份信息保存到上下文

{% highlight java linenos %}
//这里是将用户的username保存
private String getUsername(){
    String username = null;
    Authentication authentication=SecurityContextHolder.getContext().getAuthentication();
    //获取用户身份
    Object principal = authentication.getPrincipal();
    if (principal == null) {
        username = "you have to login";
    }
    if (principal instanceof org.springframework.security.core.userdetails.UserDetails) {
        UserDetails userDetails = (UserDetails) principal;
        username = userDetails.getUsername();
    }else{
        username = principal.toString();
    }
    return username;
}
{% endhighlight %}

### 3.授权

​授权有两种方式，基于web的拦截授权（拦截url）FilterSecurityInterceptor和基于方法的拦截授权MethodSecurityInterceptor。分别校验不同的授权方式。

基于web授权

http.authorizeRequests()对web资源进行保护，

{% highlight java linenos %}
//在SecurityConfig中定义的安全拦截机制
//授权管理器
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
        //search请求需要p1权限
        .antMatchers("/search").hasAnyAuthority("p1")
        //select请求需要p2或TEST权限
        .antMatchers("/select").hasAnyAuthority("p2", "TEST")
        .anyRequest().permitAll();//其他请求允许访问
}
{% endhighlight %}

基于方法授权

{% highlight java linenos %}
//在配置类上添加这个注解
@EnableGlobalMethodSecurity(prePostEnabled = true)
{% endhighlight %}

{% highlight java linenos %}
//@PostAuthorize("hasAuthority('TEST')")

//添加上这个注解，在执行该方法之前进行权限认证，拥有TEST权限才能访问方法
@PreAuthorize("hasAuthority('TEST')")
@RequestMapping("/select")
public String select(Model model) {
    model.addAttribute("username",getUsername());
    return "select";
}
{% endhighlight %}

### 4.自定义403页面

在SecurityConfig配置类上添加一个属性

{% highlight java linenos %}
//这是采用自定义处理器实现的
protected void configure(HttpSecurity http) throws Exception {
    http.exceptionHandling()
        		//没有权限（跳到403页面）
                .accessDeniedHandler(accessDeniedHandler())
        		//未登录或登录过期
                .authenticationEntryPoint(authenticationEntryPoint());
}
{% endhighlight %}

{% highlight java linenos %}
//返回页面的话
protected void configure(HttpSecurity http) throws Exception {
    http.exceptionHandling()
                .accessDeniedPage("/error/403");
}
{% endhighlight %}











