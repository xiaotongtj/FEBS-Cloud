package cc.mrbird.febs.gateway.configure;

import com.alibaba.csp.sentinel.adapter.gateway.common.SentinelGatewayConstants;
import com.alibaba.csp.sentinel.adapter.gateway.common.api.ApiDefinition;
import com.alibaba.csp.sentinel.adapter.gateway.common.api.ApiPathPredicateItem;
import com.alibaba.csp.sentinel.adapter.gateway.common.api.ApiPredicateItem;
import com.alibaba.csp.sentinel.adapter.gateway.common.api.GatewayApiDefinitionManager;
import com.alibaba.csp.sentinel.adapter.gateway.common.rule.GatewayFlowRule;
import com.alibaba.csp.sentinel.adapter.gateway.common.rule.GatewayParamFlowItem;
import com.alibaba.csp.sentinel.adapter.gateway.common.rule.GatewayRuleManager;
import com.alibaba.csp.sentinel.adapter.gateway.sc.SentinelGatewayFilter;
import com.alibaba.csp.sentinel.adapter.gateway.sc.exception.SentinelGatewayBlockExceptionHandler;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.web.reactive.result.view.ViewResolver;

import javax.annotation.PostConstruct;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @author MrBird
 */
@Configuration
public class FebsGatewaySentinelConfigure {
    private final List<ViewResolver> viewResolvers;
    private final ServerCodecConfigurer serverCodecConfigurer;

    public FebsGatewaySentinelConfigure(ObjectProvider<List<ViewResolver>> viewResolversProvider,
                                        ServerCodecConfigurer serverCodecConfigurer) {
        this.viewResolvers = viewResolversProvider.getIfAvailable(Collections::emptyList);
        this.serverCodecConfigurer = serverCodecConfigurer;
    }

    //spring gateWay 整合sentinel ,阻塞就调用处理器
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SentinelGatewayBlockExceptionHandler sentinelGatewayBlockExceptionHandler() {
        return new SentinelGatewayBlockExceptionHandler(viewResolvers, serverCodecConfigurer);
    }

    //注册一个sentinel的过滤器
    @Bean
    @Order(-1)
    public GlobalFilter sentinelGatewayFilter() {
        return new SentinelGatewayFilter();
    }

    @PostConstruct
    public void doInit() {
        initGatewayRules();
    }

    /**
     * 验证码限流 4,3点
     */
    private void initGatewayRules() {

        //自定义API规则分组(假设我有下面两个路由，我想让这两个路由共用一个限流规则)
        Set<ApiDefinition> definitions = new HashSet<>();
        Set<ApiPredicateItem> predicateItems = new HashSet<>();

        //资源
        predicateItems.add(new ApiPathPredicateItem().setPattern("/auth/captcha"));
        ApiDefinition definition = new ApiDefinition("captcha").setPredicateItems(predicateItems);
        definitions.add(definition);
        //装载定义信息
        GatewayApiDefinitionManager.loadApiDefinitions(definitions);


        //1.限流规则集合
        Set<GatewayFlowRule> rules = new HashSet<>();

        //2.配置限流规则
        rules.add(new GatewayFlowRule("captcha")
                //RESOURCE_MODE_ROUTE_ID  | RESOURCE_MODE_CUSTOM_API_NAME
                .setResourceMode(SentinelGatewayConstants.RESOURCE_MODE_CUSTOM_API_NAME)
                //[参数限流配置]。若不提供，则代表不针对参数进行限流，该网关规则将会被转换成普通流控规则；否则会转换成热点规则。其中的字段
                .setParamItem(
                        new GatewayParamFlowItem()
                                //从请求中提取参数的策略，任意 URL 参数
                                .setParseStrategy(SentinelGatewayConstants.PARAM_PARSE_STRATEGY_URL_PARAM)
                                .setFieldName("key")
                                .setMatchStrategy(SentinelGatewayConstants.PARAM_MATCH_STRATEGY_EXACT)
                                .setParseStrategy(SentinelGatewayConstants.PARAM_PARSE_STRATEGY_CLIENT_IP)
                )
                //限流阈值
                .setCount(10)
                //统计时间窗口，单位是秒，默认是 1 秒
                .setIntervalSec(60)
        );
        //3.加载限流规则集合
        GatewayRuleManager.loadRules(rules);
    }
}
