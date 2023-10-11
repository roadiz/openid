<?php
declare(strict_types=1);

namespace RZ\Roadiz\OpenId;

use Doctrine\Common\Cache\CacheProvider;
use Pimple\Container;
use Pimple\ServiceProviderInterface;
use RZ\Roadiz\JWT\JwtConfigurationFactory;
use RZ\Roadiz\OpenId\Authentication\Provider\ChainJwtRoleStrategy;
use RZ\Roadiz\OpenId\Authentication\Provider\JwtRoleStrategy;
use RZ\Roadiz\OpenId\Authentication\Provider\OAuth2AuthenticationProvider;
use RZ\Roadiz\OpenId\Authentication\Provider\OpenIdAccountProvider;
use RZ\Roadiz\OpenId\Authentication\Provider\SettingsRoleStrategy;

final class OpenIdServiceProvider implements ServiceProviderInterface
{
    /**
     * @inheritDoc
     * @return void
     */
    public function register(Container $container)
    {
        $container[JwtConfigurationFactory::class] = function (Container $c) {
            return new OpenIdJwtConfigurationFactory(
                $c[Discovery::class],
                $c['settingsBag']->get('openid_hd', null),
                $c['settingsBag']->get('oauth_client_id', null)
            );
        };

        $container[OAuth2LinkGenerator::class] = function (Container $c) {
            return new OAuth2LinkGenerator(
                $c[Discovery::class],
                $c['csrfTokenManager'],
                $c['settingsBag']->get('openid_hd', null),
                $c['settingsBag']->get('oauth_client_id', null),
                explode(' ', $c['settingsBag']->get('openid_scopes', '') ?? '')
            );
        };

        $container['jwtRoleStrategies'] = function (Container $c) {
            return [
                new SettingsRoleStrategy($c['settingsBag'])
            ];
        };

        $container[JwtRoleStrategy::class] = function (Container $c) {
            return new ChainJwtRoleStrategy($c['jwtRoleStrategies']);
        };

        $container[OAuth2AuthenticationProvider::class] = function (Container $c) {
            return new OAuth2AuthenticationProvider(
                $c[JwtConfigurationFactory::class],
                $c[JwtRoleStrategy::class],
                'roadiz_domain',
                [
                    'ROLE_USER'
                ]
            );
        };

        $container[OpenIdAccountProvider::class] = function () {
            return new OpenIdAccountProvider();
        };

        $container->extend('userProviders', function (array $providers, Container $c) {
            return array_merge($providers, [
                $c[OpenIdAccountProvider::class],
            ]);
        });

        $container->extend('authenticationProviderList', function (array $providers, Container $c) {
            return array_merge($providers, [
                $c[OAuth2AuthenticationProvider::class]
            ]);
        });

        $container[Discovery::class] = function (Container $c) {
            $discoveryUri = $c['settingsBag']->get('openid_discovery', '');
            if (!empty($discoveryUri)) {
                return new Discovery(
                    $discoveryUri,
                    $c[CacheProvider::class]
                );
            }
            return null;
        };
    }
}
