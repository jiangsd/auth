package com.jsd.auth.config;

import java.util.List;

import com.jsd.auth.filter.InitialAuthenticationFilter;
import com.jsd.auth.filter.JwtAuthenticationFilter;
import com.jsd.auth.provider.UsernamePasswordAuthenticationProvider;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // @Value("#{'${cors.origins}'.split(',')}")
    //
    // @Value("#{${cors.origins}}")
    // private List<String> corsOrigins;

    @Autowired
    private InitialAuthenticationFilter initialAuthenticationFilter;

    @Autowired
    private UsernamePasswordAuthenticationProvider usernamePasswordAuthenticationProvider;

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;


    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(usernamePasswordAuthenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
       /*  http.cors(c -> { */
            /* CorsConfigurationSource source = request -> { */
            /*     CorsConfiguration config = new CorsConfiguration(); */
            /*     config.setAllowedOrigins( */
            /*             // List.of("http://cmsfrontend.com", "http://cmsfrontend.com:3000")); */
            /*             // List.of("http://192.168.1.88", "http://192.168.1.88:3000")); */
            /*             corsOrigins); */
            /*     config.addAllowedHeader("*"); */
            /*     config.setAllowedMethods( */
            /*             List.of("GET", "PUT", "POST", "DELETE", "OPTIONS")); */
            /*     return config; */
            /* }; */
            /* c.configurationSource(source); */
        /* }); */

        // http.cors();
        // http.httpBasic();
        http.csrf().disable();
        // http.authorizeRequests().anyRequest().permitAll();

        http.addFilterAt(initialAuthenticationFilter, BasicAuthenticationFilter.class)
            .addFilterAfter(jwtAuthenticationFilter, BasicAuthenticationFilter.class);

        // http.authorizeRequests().antMatchers("/v/resetPassword*").permitAll();
        // http.authorizeRequests().anyRequest().authenticated();
        http.authorizeRequests()
            .antMatchers("/v1/resetPassword*").permitAll()
            .anyRequest().authenticated();
    }

    @Override
    @Bean
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }
}
