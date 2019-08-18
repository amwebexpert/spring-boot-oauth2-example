package com.example.simple

import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.oauth2.client.OAuth2ClientContext
import org.springframework.security.oauth2.client.OAuth2RestTemplate
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.security.web.csrf.CookieCsrfTokenRepository
import org.springframework.web.filter.CompositeFilter
import java.util.*
import javax.servlet.Filter


@Configuration
@EnableWebSecurity
@EnableOAuth2Client
class SecurityConfiguration(val oauth2ClientContext: OAuth2ClientContext) : WebSecurityConfigurerAdapter() {

    override fun configure(http: HttpSecurity) {
        // @formatter:off
        http.antMatcher("/**").authorizeRequests().antMatchers("/", "/login**", "/webjars/**", "/*.ico", "/error**").permitAll().anyRequest().authenticated()
                .and()
                .exceptionHandling().authenticationEntryPoint(LoginUrlAuthenticationEntryPoint("/"))
                .and()
                .logout().logoutSuccessUrl("/").permitAll()
                .and()
                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()
                .addFilterBefore(ssoCompositeFilter(), BasicAuthenticationFilter::class.java)
        // @formatter:on
    }

    private fun ssoCompositeFilter(): Filter {
        val filter = CompositeFilter()
        val filters = ArrayList<Filter>()

        val facebookFilter = OAuth2ClientAuthenticationProcessingFilter("/login/facebook")
        val facebookTemplate = OAuth2RestTemplate(facebook(), oauth2ClientContext)
        facebookFilter.setRestTemplate(facebookTemplate)
        var tokenServices = UserInfoTokenServices(facebookResource().userInfoUri, facebook().clientId)
        tokenServices.setRestTemplate(facebookTemplate)
        facebookFilter.setTokenServices(tokenServices)
        filters.add(facebookFilter)

        val githubFilter = OAuth2ClientAuthenticationProcessingFilter("/login/github")
        val githubTemplate = OAuth2RestTemplate(github(), oauth2ClientContext)
        githubFilter.setRestTemplate(githubTemplate)
        tokenServices = UserInfoTokenServices(githubResource().getUserInfoUri(), github().getClientId())
        tokenServices.setRestTemplate(githubTemplate)
        githubFilter.setTokenServices(tokenServices)
        filters.add(githubFilter)

        filter.setFilters(filters)
        return filter

    }

    @Bean

    fun oauth2ClientFilterRegistration(filter: OAuth2ClientContextFilter): FilterRegistrationBean<OAuth2ClientContextFilter> {
        val registration = FilterRegistrationBean<OAuth2ClientContextFilter>()
        registration.filter = filter
        registration.order = -100
        return registration
    }

    @Bean
    @ConfigurationProperties("facebook.client")
    fun facebook(): AuthorizationCodeResourceDetails {
        return AuthorizationCodeResourceDetails()
    }

    @Bean
    @ConfigurationProperties("facebook.resource")
    fun facebookResource(): ResourceServerProperties {
        return ResourceServerProperties()
    }

    @Bean
    @ConfigurationProperties("github.client")
    fun github(): AuthorizationCodeResourceDetails {
        return AuthorizationCodeResourceDetails()
    }

    @Bean
    @ConfigurationProperties("github.resource")
    fun githubResource(): ResourceServerProperties {
        return ResourceServerProperties()
    }

}