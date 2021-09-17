<?php
declare(strict_types=1);

namespace RZ\Roadiz\OpenId;

use RZ\Roadiz\OpenId\Authentication\OAuth2AuthenticationListener;
use RZ\Roadiz\OpenId\Exception\DiscoveryNotAvailableException;
use RZ\Roadiz\Random\TokenGenerator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

class OAuth2LinkGenerator
{
    protected ?Discovery $discovery;
    protected CsrfTokenManagerInterface $csrfTokenManager;
    private ?string $openIdHostedDomain;
    private ?string $oauthClientId;
    private ?array $openIdScopes;

    public function __construct(
        ?Discovery $discovery,
        CsrfTokenManagerInterface $csrfTokenManager,
        ?string $openIdHostedDomain,
        ?string $oauthClientId,
        ?array $openIdScopes
    ) {
        $this->discovery = $discovery;
        $this->csrfTokenManager = $csrfTokenManager;
        $this->openIdHostedDomain = $openIdHostedDomain;
        $this->oauthClientId = $oauthClientId;
        $this->openIdScopes = $openIdScopes;
    }

    /**
     * @param Request $request
     *
     * @return bool
     */
    public function isSupported(Request $request): bool
    {
        return null !== $this->discovery;
    }

    /**
     * @param Request $request
     * @param string  $redirectUri
     * @param array   $state
     * @param string  $responseType
     *
     * @return string
     */
    public function generate(Request $request, string $redirectUri, array $state = [], string $responseType = 'code'): string
    {
        if (null !== $this->discovery &&
            in_array($responseType, $this->discovery->get('response_types_supported', []))) {
            if (!empty($this->openIdScopes)) {
                $customScopes = array_intersect(
                    $this->openIdScopes,
                    $this->discovery->get('scopes_supported')
                );
            } else {
                $customScopes = $this->discovery->get('scopes_supported');
            }
            $stateToken = $this->csrfTokenManager->getToken(OAuth2AuthenticationListener::OAUTH_STATE_TOKEN);
            return $this->discovery->get('authorization_endpoint') . '?' . http_build_query([
                'response_type' => 'code',
                'hd' => $this->openIdHostedDomain,
                'state' => http_build_query(array_merge($state, [
                    'token' => $stateToken->getValue()
                ])),
                'nonce' => (new TokenGenerator())->generateToken(),
                'login_hint' => $request->get('email', null),
                'scope' => implode(' ', $customScopes),
                'client_id' => $this->oauthClientId,
                'redirect_uri' => $redirectUri,
            ]);
        }
        throw new DiscoveryNotAvailableException(
            'OpenID discovery is not well configured or response_type is not supported by your identity provider'
        );
    }
}
