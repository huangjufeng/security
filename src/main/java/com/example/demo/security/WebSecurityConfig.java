package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.filter.CharacterEncodingFilter;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	//UserDetailsService在身份认证中的作用
	@Autowired
	private UserDetailsService myCustomUserService;
	
	//Security加密——PasswordEncoder的实现类
    private MyPasswordEncoder myPasswordEncoder;

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		//跨域资源共享(CORS),csrf估计手段，这些禁用
		http.cors().and().csrf().disable();
	
		
		http
		//使用form表单的post方法进行登录
		.formLogin()
		//登录页面为自定义的login页面
		.loginPage("/login")
		//设置登录成功跳转的页面，error=true控制页面错误信息的展示
		.successForwardUrl("/index").failureUrl("/login?erroe=true")
		
		//anonymous() 允许匿名用户访问
		//permitAll() 无条件允许访问
		.permitAll()
		.and()//和
		//允许不登录就可以访问的方法，多个用逗号分隔
		.authorizeRequests().antMatchers("/test").permitAll()
		//其他的需要授权后访问
		.anyRequest().authenticated();
		
		//session管理，失效后跳转login页面
		http.sessionManagement().invalidSessionUrl("/login");
		
		//单用户登录，如果一个登录了，同一个用户在其他地方不能登录
		http.sessionManagement().maximumSessions(1).maxSessionsPreventsLogin(true);
		
		//退出时情况cookies
		http.logout().deleteCookies("JESSIONID");
		
		//解决中文乱码问题
		CharacterEncodingFilter filter = new CharacterEncodingFilter();
		
		filter.setEncoding("UTF-8");
		//强转
		filter.setForceEncoding(true);
		
	}

    @Bean
    // 授权方式提供者
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider bean = new DaoAuthenticationProvider();
        //返回错误信息提示，而不是Bad Credential
        bean.setHideUserNotFoundExceptions(true);
        //覆盖UserDetailsService类
        bean.setUserDetailsService(myCustomUserService);
        //覆盖默认的密码验证类
        bean.setPasswordEncoder(myPasswordEncoder); 
        return bean;
    }

	
}
