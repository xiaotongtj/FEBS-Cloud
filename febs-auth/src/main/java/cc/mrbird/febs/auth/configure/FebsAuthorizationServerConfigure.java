package cc.mrbird.febs.auth.configure;

import cc.mrbird.febs.auth.properties.FebsAuthProperties;
import cc.mrbird.febs.auth.service.impl.FebsUserDetailService;
import cc.mrbird.febs.auth.service.impl.RedisClientDetailsService;
import cc.mrbird.febs.auth.translator.FebsWebResponseExceptionTranslator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.password.ResourceOwnerPasswordTokenGranter;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

import java.util.UUID;

/**
 * 认证服务器配置
 *
 * @author MrBird
 */
@Configuration
@EnableAuthorizationServer
public class FebsAuthorizationServerConfigure extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private FebsUserDetailService userDetailService;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private FebsWebResponseExceptionTranslator exceptionTranslator;
    @Autowired
    private FebsAuthProperties properties;
    @Autowired
    private RedisClientDetailsService redisClientDetailsService;
    @Autowired
    private RedisConnectionFactory redisConnectionFactory;

    //ClientDetailsServiceConfigurer 能够使用内存或 JDBC 方式实现【获取已注册的客户端详情】
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        //这里是基于JDBC-->redis来实现客户端的信息查询
        clients.withClientDetails(redisClientDetailsService);
    }

    //配置授权类型（Grant Types）的管理

    /**
     * 配置授权服务器端点，如令牌存储，令牌自定义，用户批准和授权类型，不包括端点安全配置
     *
     *
     * 下面是一些默认的端点 URL：
     *
     * /oauth/authorize：授权端点
     * /oauth/token：令牌端点
     * /oauth/confirm_access：用户确认授权提交端点
     * /oauth/error：授权服务错误信息端点
     * /oauth/check_token：用于资源服务访问的令牌解析端点
     * /oauth/token_key：提供公有密匙的端点，如果你使用JWT令牌的话
     *
     */
    @Override
    @SuppressWarnings("unchecked")
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints.tokenStore(tokenStore()) //令牌的存储
                .userDetailsService(userDetailService)
                .authenticationManager(authenticationManager) //默认的认证管理器
                .exceptionTranslator(exceptionTranslator);   //异常的翻译类
        if (properties.getEnableJwt()) {
            endpoints.accessTokenConverter(jwtAccessTokenConverter()); //添加jwt的转换
        }
    }

    /**
     * InMemoryTokenStore：默认采用该实现，将令牌信息保存在内存中，易于调试
     * JdbcTokenStore：令牌会被保存近关系型数据库，可以在不同服务器之间共享令牌
     * JwtTokenStore：使用 JWT 方式保存令牌，它不需要进行存储，但是它撤销一个已经授权令牌会非常困难，所以通常用来处理一个生命周期较短的令牌以及撤销刷新令牌
     */
    @Bean
    public TokenStore tokenStore() {
        if (properties.getEnableJwt()) {
            //使用jwt方式进行存储
            /**
             * jwt 验证通过使用 userDetailService返回用户新
             */
            return new JwtTokenStore(jwtAccessTokenConverter());
        } else {
            /**
             * redis 验证通过使用 redisClientDetailsService
             */
            RedisTokenStore redisTokenStore = new RedisTokenStore(redisConnectionFactory);
            // 解决每次生成的 token都一样的问题
            redisTokenStore.setAuthenticationKeyGenerator(oAuth2Authentication -> UUID.randomUUID().toString());
            return redisTokenStore;
        }
    }

    //创建令牌、读取令牌、刷新令牌、获取客户端ID。默认的当尝试创建一个令牌时，是使用 UUID 随机值进行填充的，除了持久化令牌是委托一个 TokenStore 接口实现以外
    @Bean
    @Primary
    public DefaultTokenServices defaultTokenServices() {
        DefaultTokenServices tokenServices = new DefaultTokenServices();

        tokenServices.setTokenStore(tokenStore());
        tokenServices.setSupportRefreshToken(true);
        tokenServices.setClientDetailsService(redisClientDetailsService);
        return tokenServices;
    }

    /**
     * TokenEnhancer
     * 可用于自定义令牌策略，在令牌被 AuthorizationServerTokenServices 的实现存储之前增强令牌的策略，它有两个实现类：
     * JwtAccessTokenConverter：用于令牌 JWT 编码与解码
     * TokenEnhancerChain：一个令牌链，可以存放多个令牌，并循环的遍历令牌并将结果传递给下一个令牌
     *
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
        DefaultAccessTokenConverter defaultAccessTokenConverter = (DefaultAccessTokenConverter) accessTokenConverter.getAccessTokenConverter();
        DefaultUserAuthenticationConverter userAuthenticationConverter = new DefaultUserAuthenticationConverter();

        userAuthenticationConverter.setUserDetailsService(userDetailService);
        defaultAccessTokenConverter.setUserTokenConverter(userAuthenticationConverter);

        accessTokenConverter.setSigningKey(properties.getJwtAccessKey());
        return accessTokenConverter;
    }

    //认证服务和资源服务的一个过渡类
    @Bean
    public ResourceOwnerPasswordTokenGranter resourceOwnerPasswordTokenGranter(AuthenticationManager authenticationManager, OAuth2RequestFactory oAuth2RequestFactory) {
        DefaultTokenServices defaultTokenServices = defaultTokenServices();
        if (properties.getEnableJwt()) {
            defaultTokenServices.setTokenEnhancer(jwtAccessTokenConverter());
        }
        return new ResourceOwnerPasswordTokenGranter(authenticationManager, defaultTokenServices, redisClientDetailsService, oAuth2RequestFactory);
    }

    @Bean
    public DefaultOAuth2RequestFactory oAuth2RequestFactory() {
        return new DefaultOAuth2RequestFactory(redisClientDetailsService);
    }

}
