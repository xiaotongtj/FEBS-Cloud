package cc.mrbird.febs.auth.configure;

import cc.mrbird.febs.auth.properties.FebsAuthProperties;
import cc.mrbird.febs.common.entity.constant.EndpointConstant;
import cc.mrbird.febs.common.handler.FebsAccessDeniedHandler;
import cc.mrbird.febs.common.handler.FebsAuthExceptionEntryPoint;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;

/**
 * 资源服务器配置
 *
 * @author MrBird
 */
@Configuration
@EnableResourceServer
public class FebsResourceServerConfigure extends ResourceServerConfigurerAdapter {

    //资源被拒绝处理器
    @Autowired
    private FebsAccessDeniedHandler accessDeniedHandler;
    @Autowired
    private FebsAuthExceptionEntryPoint exceptionEntryPoint;
    @Autowired
    private FebsAuthProperties properties;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        //不认证的URLs
        String[] anonUrls = StringUtils.splitByWholeSeparatorPreserveAllTokens(properties.getAnonUrl(), ",");

        //禁用跨站点攻击
        http.csrf().disable()
                .requestMatchers().antMatchers(EndpointConstant.ALL)
                .and()
                .authorizeRequests()
                .antMatchers(anonUrls).permitAll()
                .antMatchers(EndpointConstant.ALL).authenticated()
                .and().httpBasic(); //基于简单认证
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        //匿名用户认证访问需要权限的资源
        resources.authenticationEntryPoint(exceptionEntryPoint)
                .accessDeniedHandler(accessDeniedHandler);
    }
}
