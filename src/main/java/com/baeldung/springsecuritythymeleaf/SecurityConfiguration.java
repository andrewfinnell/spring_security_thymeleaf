package com.baeldung.springsecuritythymeleaf;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Collection;

import static java.util.Arrays.asList;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private AccessDeniedHandler accessDeniedHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http.csrf()
                .disable()
                    .authorizeRequests()
                        .antMatchers("/", "/home", "/about")
                            .permitAll()
                        .antMatchers("/admin/**")
                            .hasAnyRole("ADMIN")
                        .antMatchers("/user/**", "/test/**")
                            .hasAnyRole("USER")
                        .anyRequest()
                            .authenticated()
                                .and()
                            .formLogin()
                                .loginPage("/login")
                        .permitAll()
                            .and()
                                .logout()
                        .permitAll()
                            .and()
                        .exceptionHandling()
                    .accessDeniedHandler(accessDeniedHandler);
        // @formatter:on
//        http.authorizeRequests()
//            .anyRequest()
//            .authenticated()
//            .and()
//            .formLogin()
//            .loginPage("/login")
//            .permitAll()
//            .successForwardUrl("/index")
//            .and()
//            .logout()
//            .permitAll()
//            .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
//            .logoutSuccessUrl("/login");
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {

//        auth.authenticationProvider(new AuthenticationProvider() {
//            @Override
//            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//
//                UsernamePasswordAuthenticationToken token =
//                        new UsernamePasswordAuthenticationToken(
//                                authentication.getPrincipal(),
//                                authentication.getCredentials(),
//                                asList(
//                                        new SimpleGrantedAuthority("ROLE_ADMIN"),
//                                        new SimpleGrantedAuthority("ROLE_USER")
//                                ));
//
//                return token;
//            }
//
//            @Override
//            public boolean supports(Class<?> aClass) {
//                return true;
//            }
//        });

        // @formatter:off
        auth.inMemoryAuthentication()
                .withUser("user")
                    .password(passwordEncoder().encode("password"))
                        .roles("USER")
                .and()
                    .withUser("admin")
                        .password(passwordEncoder().encode("password"))
                            .roles("USER", "ADMIN");
        // @formatter:on
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
