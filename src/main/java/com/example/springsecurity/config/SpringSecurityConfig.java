package com.example.springsecurity.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

//    @Bean
//    @Override
//    protected UserDetailsService userDetailsService() {
//        return new InMemoryUserDetailsManager
//                (
//                        User.builder().username("anar").password(passwordEncoder().encode("anar")).roles("ADMIN").build(),
//                        User.builder().username("yasin").password(passwordEncoder().encode("yasin")).roles("MANAGER").build()
//                );
//    }

//    @Bean
//    @Override
//    protected UserDetailsService userDetailsService() {
//        UserDetails yasin = User.builder().username("Yasin").password(passwordEncoder().encode("yasin123")).roles("ADMIN").build();
//        UserDetails anar = User.builder().username("Anar").password(passwordEncoder().encode("anar123")).roles("MANAGER").build();
//        return new InMemoryUserDetailsManager(yasin, anar);
//
//        //belede yaza bilerik
////        InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager();
////        userDetailsManager.createUser(yasin);
////        userDetailsManager.createUser(anar);
////        return userDetailsManager;
//    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .withUser("Yasin")
//                .password(passwordEncoder().encode("yasin"))
//                .roles("ADMIN")
//                .and()
//                .withUser("Ali")
//                .password(passwordEncoder().encode("ali"))
//                .roles("MANAGER");
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers(HttpMethod.GET, "/**").permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }


//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.
//                httpBasic().and()
//                .authorizeRequests()
//                .antMatchers(HttpMethod.GET,"/**").permitAll()
//                .antMatchers("/delete").hasRole("ADMIN")
//                .antMatchers("/details").hasAnyRole("ADMIN","MANAGER")
//                .and()
//                .formLogin();
//    }


//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers("/").permitAll()
//                .antMatchers("/new").hasAnyRole("USER","ADMIN")
//                .antMatchers("/edit/*","/delete/*").hasRole("ADMIN")
//                .anyRequest().authenticated()
//                .and()
//                .httpBasic()
//                .and()
//                .exceptionHandling().accessDeniedPage("/403");
//    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

//    @Override
//    public void configure(WebSecurity web) throws Exception {
//        web
//                .ignoring()
//                .antMatchers("/error-page",
//                        "/assets/**",
//                        "/resources/**",
//                        "/upload/**",
//                        "/asserts/**",
//                        "/static/**",
//                        "/css/**",
//                        "/js/**",
//                        "/images/**");
//    }

}
